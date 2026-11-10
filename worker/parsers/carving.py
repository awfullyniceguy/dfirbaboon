"""Unallocated-space extraction (blkls), file carving (PhotoRec with built-in fallback), EXIF extraction and keyword triage.

Runs once per volume (see run_carving). Timeouts come from DFIR_TOOL_TIMEOUT_SEC; any reduced coverage (failed tool,
keyword scan cap, ...) is recorded in CarvingResult.warnings rather than being hidden.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import mmap
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .base import BaseParser, ParserContext, ParserFactory, ParserResult
    from .tsk_parser import ExtractedFileRecord, tool_timeout
except ImportError:
    from parsers.base import BaseParser, ParserContext, ParserFactory, ParserResult
    from parsers.tsk_parser import ExtractedFileRecord, tool_timeout

logger = logging.getLogger("dfirbaboon.carving")

MEDIA_EXTENSIONS = frozenset(
    {"jpg", "jpeg", "png", "gif", "bmp", "ico", "tif", "tiff", "webp", "mp3", "wav", "avi", "mp4", "mov", "swf", "swc"}
)
EXIF_EXTENSIONS = ("jpg", "jpeg", "tif", "tiff", "png")

# (label, regex) triage patterns applied to unallocated space.
KEYWORD_PATTERNS: List[Tuple[str, "re.Pattern[bytes]"]] = [
    (
        "credential_assignment",
        re.compile(rb"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*\S{3,}"),
    ),
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("email_address", re.compile(rb"[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("url", re.compile(rb"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{6,200}")),
    ("onion_address", re.compile(rb"[a-z2-7]{16,56}\.onion")),
    ("ipv4_address", re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("us_ssn_pattern", re.compile(rb"\b\d{3}-\d{2}-\d{4}\b")),
]

DEFAULT_CUSTOM_KEYWORDS = "confidential,malware,backdoor,exploit,ransom,keylogger,exfil"
DEFAULT_KEYWORD_MAX_BYTES = 64 * 1024 * 1024 * 1024

# (extension, header(s), footer, max size) for the built-in fallback carver.
BUILTIN_SIGNATURES: List[Tuple[str, Tuple[bytes, ...], bytes, int]] = [
    ("jpg", (b"\xff\xd8\xff",), b"\xff\xd9", 30 * 1024 * 1024),
    ("png", (b"\x89PNG\r\n\x1a\n",), b"IEND\xaeB`\x82", 30 * 1024 * 1024),
    ("gif", (b"GIF87a", b"GIF89a"), b"\x00\x3b", 30 * 1024 * 1024),
    ("pdf", (b"%PDF-",), b"%%EOF", 100 * 1024 * 1024),
]


@dataclass
class CarvedFile:
    """A file recovered from unallocated space."""

    name: str
    extension: str
    size_bytes: int
    sha256: str
    unalloc_offset: int
    local_path: str
    volume_offset: int = 0


@dataclass
class KeywordFinding:
    """Aggregated hits for one keyword/triage pattern in unallocated space."""

    label: str
    total: int
    unique: int
    samples: List[Tuple[str, int, int]] = field(default_factory=list)  # (value, count, first_offset)


@dataclass
class CarvingResult:
    """Everything produced by unallocated-space analysis."""

    attempted: bool = False
    skipped_reason: str = ""
    unallocated_paths: List[str] = field(default_factory=list)
    unallocated_bytes: int = 0
    carver: str = "none"
    carved_files: List[CarvedFile] = field(default_factory=list)
    type_counts: Dict[str, int] = field(default_factory=dict)
    type_bytes: Dict[str, int] = field(default_factory=dict)
    exif_records: List[Dict[str, Any]] = field(default_factory=list)
    keyword_findings: List[KeywordFinding] = field(default_factory=list)
    keyword_bytes_scanned: int = 0
    inventory_csv_path: str = ""
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class CarvingEngine:
    """Extracts unallocated space with blkls, carves files, pulls EXIF, and triages keywords for one volume."""

    def __init__(self, image_path: str, work_dir: str) -> None:
        self.image_path = str(Path(image_path).resolve())
        self.work_dir = Path(work_dir).resolve()
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.carve_dir = self.work_dir / "carved"
        self.carve_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ blkls
    def extract_unallocated(self, offset: int) -> Tuple[Optional[Path], str]:
        """Run blkls -o <offset> <image> to dump unallocated blocks into a single file."""
        out_path = self.work_dir / "unallocated.bin"
        logger.info("Extracting unallocated space: blkls -o %d %s", offset, self.image_path)
        try:
            with out_path.open("wb") as handle:
                proc = subprocess.run(
                    ["blkls", "-o", str(offset), self.image_path],
                    stdout=handle, stderr=subprocess.PIPE, timeout=tool_timeout(), check=False,
                )
        except FileNotFoundError:
            out_path.unlink(missing_ok=True)
            return None, "blkls binary not found"
        except subprocess.TimeoutExpired:
            out_path.unlink(missing_ok=True)
            return None, "blkls timed out extracting unallocated space"
        except (OSError, subprocess.SubprocessError) as exc:
            out_path.unlink(missing_ok=True)
            return None, f"blkls failed: {exc}"

        if proc.returncode != 0 or not out_path.exists() or out_path.stat().st_size == 0:
            err = proc.stderr.decode("utf-8", errors="replace").strip()[:300]
            out_path.unlink(missing_ok=True)
            return None, f"blkls returned {proc.returncode}: {err or 'no unallocated blocks'}"
        return out_path, ""

    # ---------------------------------------------------------------- carving
    def _carve_photorec(self, unalloc: Path) -> Tuple[bool, str]:
        out_dir = self.carve_dir / "photorec"
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            "photorec", "/d", str(out_dir) + "/", "/cmd", str(unalloc),
            "partition_none,fileopt,everything,enable,search",
        ]
        logger.info("Carving unallocated space: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=tool_timeout(), check=False,
            )
        except FileNotFoundError:
            return False, "photorec binary not found"
        except subprocess.TimeoutExpired:
            return False, "photorec timed out; carved file set may be incomplete"
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"photorec failed: {exc}"
        if proc.returncode != 0:
            return False, f"photorec returned {proc.returncode}"
        return True, ""

    def _carve_builtin(self, unalloc: Path, max_files: int = 5000) -> int:
        """Header/footer signature carver (JPEG, PNG, GIF, PDF) used when PhotoRec is unavailable."""
        out_dir = self.carve_dir / "builtin"
        out_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        if unalloc.stat().st_size == 0:
            return 0
        with unalloc.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            total = len(mm)
            for ext, headers, footer, max_size in BUILTIN_SIGNATURES:
                for header in headers:
                    pos = 0
                    while count < max_files:
                        start = mm.find(header, pos)
                        if start == -1:
                            break
                        end = mm.find(footer, start + len(header), min(total, start + max_size))
                        if end == -1:
                            pos = start + len(header)
                            continue
                        end += len(footer)
                        (out_dir / f"b{start:012d}.{ext}").write_bytes(mm[start:end])
                        count += 1
                        pos = end
        return count

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _collect_carved(self, volume_offset: int = 0) -> List[CarvedFile]:
        carved: List[CarvedFile] = []
        for root, _dirs, files in os.walk(self.carve_dir):
            for fname in sorted(files):
                fpath = Path(root) / fname
                if fname.startswith("photorec") and fpath.suffix.lower() in (".ses", ".log"):
                    continue
                try:
                    size = fpath.stat().st_size
                    sha256 = self._sha256_file(fpath)
                except OSError:
                    continue
                stem = fpath.stem
                offset = 0
                digits = re.sub(r"^[a-zA-Z]+", "", stem)
                if digits.isdigit():
                    # PhotoRec names files f<sector>; builtin names b<byte_offset>.
                    offset = int(digits) * (512 if stem.startswith("f") else 1)
                carved.append(
                    CarvedFile(
                        name=fname,
                        extension=fpath.suffix.lower().lstrip(".") or "noext",
                        size_bytes=size,
                        sha256=sha256,
                        unalloc_offset=offset,
                        local_path=str(fpath),
                        volume_offset=volume_offset,
                    )
                )
        return carved

    # ------------------------------------------------------------------- EXIF
    def extract_exif(self, limit: int = 500) -> List[Dict[str, Any]]:
        cmd = ["exiftool", "-json", "-n", "-q", "-r"]
        for ext in EXIF_EXTENSIONS:
            cmd += ["-ext", ext]
        cmd += [
            "-Make", "-Model", "-DateTimeOriginal", "-CreateDate", "-Software",
            "-Artist", "-GPSLatitude", "-GPSLongitude", "-ImageWidth", "-ImageHeight",
            str(self.carve_dir),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=min(tool_timeout(), 3600), check=False)
        except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
            logger.warning("exiftool unavailable or failed: %s", exc)
            return []
        if not proc.stdout.strip():
            return []
        try:
            records = json.loads(proc.stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return []
        interesting = ("Make", "Model", "DateTimeOriginal", "CreateDate", "Software", "Artist", "GPSLatitude")
        kept = [r for r in records if any(r.get(k) for k in interesting)]
        for rec in kept:
            rec["SourceFile"] = Path(str(rec.get("SourceFile", ""))).name
        return kept[:limit]

    # --------------------------------------------------------------- keywords
    def scan_keywords(
        self,
        unalloc: Path,
        max_scan_bytes: Optional[int] = None,
        chunk_size: int = 16 * 1024 * 1024,
    ) -> Tuple[List[KeywordFinding], int]:
        if max_scan_bytes is None:
            try:
                max_scan_bytes = int(os.environ.get("DFIR_KEYWORD_MAX_BYTES", DEFAULT_KEYWORD_MAX_BYTES))
            except ValueError:
                max_scan_bytes = DEFAULT_KEYWORD_MAX_BYTES

        patterns = list(KEYWORD_PATTERNS)
        custom = os.environ.get("DFIR_KEYWORDS", DEFAULT_CUSTOM_KEYWORDS)
        words = [w.strip() for w in custom.split(",") if w.strip()]
        if words:
            patterns.append(
                ("custom_keyword", re.compile(b"(?i)(?:" + b"|".join(re.escape(w.encode()) for w in words) + b")"))
            )

        totals: Dict[str, int] = {label: 0 for label, _ in patterns}
        values: Dict[str, Dict[str, List[int]]] = {label: {} for label, _ in patterns}
        scanned = 0
        tail = b""
        overlap = 512

        with unalloc.open("rb") as handle:
            while scanned < max_scan_bytes:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                data = tail + chunk
                base = scanned - len(tail)
                for label, rx in patterns:
                    for m in rx.finditer(data):
                        if m.end() <= len(tail):
                            continue  # already matched in previous chunk
                        totals[label] += 1
                        val = m.group(0).decode("latin-1", errors="replace")[:160]
                        bucket = values[label]
                        if val in bucket:
                            bucket[val][0] += 1
                        elif len(bucket) < 5000:
                            bucket[val] = [1, base + m.start()]
                scanned += len(chunk)
                tail = data[-overlap:]

        findings: List[KeywordFinding] = []
        for label, _ in patterns:
            if totals[label] == 0:
                continue
            top = sorted(values[label].items(), key=lambda kv: kv[1][0], reverse=True)[:15]
            findings.append(
                KeywordFinding(
                    label=label,
                    total=totals[label],
                    unique=len(values[label]),
                    samples=[(v, c[0], c[1]) for v, c in top],
                )
            )
        return findings, scanned

    # -------------------------------------------------------------- orchestration
    def run(self, offset: int) -> CarvingResult:
        """Run the full carving pipeline for the volume starting at sector `offset`."""
        result = CarvingResult(attempted=True)
        unalloc, err = self.extract_unallocated(offset)
        if unalloc is None:
            result.skipped_reason = err
            result.warnings.append(f"Volume @{offset}: unallocated-space analysis skipped ({err}).")
            return result

        result.unallocated_paths = [str(unalloc)]
        result.unallocated_bytes = unalloc.stat().st_size

        ok, photorec_err = self._carve_photorec(unalloc)
        carved = self._collect_carved(offset) if ok else []
        if ok and carved:
            result.carver = "photorec"
        else:
            if photorec_err:
                result.warnings.append(f"Volume @{offset}: {photorec_err}")
            builtin_count = self._carve_builtin(unalloc)
            carved = self._collect_carved(offset)
            result.carver = "builtin-signature-carver" if builtin_count else ("photorec" if ok else "none")
            if builtin_count:
                result.notes.append(f"Volume @{offset}: used built-in JPEG/PNG/GIF/PDF signature carver.")

        result.carved_files = carved
        for c in carved:
            result.type_counts[c.extension] = result.type_counts.get(c.extension, 0) + 1
            result.type_bytes[c.extension] = result.type_bytes.get(c.extension, 0) + c.size_bytes

        result.exif_records = self.extract_exif()
        result.keyword_findings, result.keyword_bytes_scanned = self.scan_keywords(unalloc)
        if result.keyword_bytes_scanned < result.unallocated_bytes:
            result.warnings.append(
                f"Volume @{offset}: keyword scan covered {result.keyword_bytes_scanned:,} of "
                f"{result.unallocated_bytes:,} unallocated bytes (DFIR_KEYWORD_MAX_BYTES cap)."
            )
        logger.info(
            "Carving complete (volume @%d): carver=%s files=%d types=%d exif=%d keyword_patterns_hit=%d",
            offset, result.carver, len(carved), len(result.type_counts), len(result.exif_records),
            len(result.keyword_findings),
        )
        return result

    @staticmethod
    def to_scan_records(
        carved: List[CarvedFile], limit: int = 2000, max_size: int = 50 * 1024 * 1024
    ) -> List[ExtractedFileRecord]:
        """Select non-media carved files for YARA / header anomaly scanning."""
        records: List[ExtractedFileRecord] = []
        for c in carved:
            if c.extension in MEDIA_EXTENSIONS or c.size_bytes == 0 or c.size_bytes > max_size:
                continue
            records.append(
                ExtractedFileRecord(
                    inode="carved",
                    original_path=f"$CarvedFiles/{c.name}",
                    local_path=c.local_path,
                    size_bytes=c.size_bytes,
                    is_deleted=False,
                )
            )
            if len(records) >= limit:
                break
        return records


def _merge_results(results: List[CarvingResult]) -> CarvingResult:
    """Combine per-volume carving results into one."""
    merged = CarvingResult(attempted=True)
    carvers = set()
    keyword_map: Dict[str, KeywordFinding] = {}
    for res in results:
        merged.unallocated_paths.extend(res.unallocated_paths)
        merged.unallocated_bytes += res.unallocated_bytes
        merged.carved_files.extend(res.carved_files)
        for ext, cnt in res.type_counts.items():
            merged.type_counts[ext] = merged.type_counts.get(ext, 0) + cnt
        for ext, size in res.type_bytes.items():
            merged.type_bytes[ext] = merged.type_bytes.get(ext, 0) + size
        merged.exif_records.extend(res.exif_records)
        merged.keyword_bytes_scanned += res.keyword_bytes_scanned
        merged.notes.extend(res.notes)
        merged.warnings.extend(res.warnings)
        if res.carver != "none":
            carvers.add(res.carver)
        for finding in res.keyword_findings:
            cur = keyword_map.get(finding.label)
            if cur is None:
                keyword_map[finding.label] = KeywordFinding(finding.label, finding.total, finding.unique, list(finding.samples))
            else:
                cur.total += finding.total
                cur.unique += finding.unique
                cur.samples = sorted(cur.samples + finding.samples, key=lambda s: s[1], reverse=True)[:15]
    merged.keyword_findings = list(keyword_map.values())
    merged.carver = "+".join(sorted(carvers)) if carvers else "none"
    if not merged.unallocated_paths:
        merged.skipped_reason = "; ".join(r.skipped_reason for r in results if r.skipped_reason)
    return merged


def run_carving(
    image_path: str,
    work_dir: str,
    volume_offsets: List[int],
    max_parallel_volumes: int = 2,
) -> CarvingResult:
    """Carve every volume (up to `max_parallel_volumes` at a time) and write one combined inventory CSV."""
    base = Path(work_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)
    if not volume_offsets:
        return CarvingResult(
            attempted=False,
            skipped_reason="No recognizable file system; unallocated-space analysis not applicable.",
        )

    def _one(idx_offset: Tuple[int, int]) -> CarvingResult:
        idx, offset = idx_offset
        try:
            return CarvingEngine(image_path, str(base / f"vol{idx}")).run(offset)
        except Exception as exc:  # noqa: BLE001 - surfaced as explicit warning
            logger.exception("Carving crashed for volume @%d", offset)
            res = CarvingResult(attempted=True, skipped_reason=str(exc))
            res.warnings.append(f"Volume @{offset}: carving crashed ({exc}).")
            return res

    with ThreadPoolExecutor(max_workers=max(1, min(max_parallel_volumes, len(volume_offsets)))) as pool:
        results = list(pool.map(_one, list(enumerate(volume_offsets))))

    merged = _merge_results(results)
    inventory = base / "carved_files_inventory.csv"
    with inventory.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["volume_offset_sector", "name", "extension", "size_bytes", "sha256", "unallocated_offset_bytes"])
        for c in merged.carved_files:
            writer.writerow([c.volume_offset, c.name, c.extension, c.size_bytes, c.sha256, c.unalloc_offset])
    merged.inventory_csv_path = str(inventory)
    return merged


class CarvingForensicParser(BaseParser):
    """ForensicParser plugin implementation for blkls extraction, PhotoRec carving, and keyword triage."""

    def get_parser_name(self) -> str:
        return "carving"

    def get_parser_type(self) -> str:
        return "carver"

    def validate(self, evidence_path: Path) -> bool:
        return evidence_path.is_file() and evidence_path.stat().st_size > 0

    def parse(self, context: ParserContext) -> ParserResult:
        if not context.config.enable_carving:
            return ParserResult(
                parser_name=self.get_parser_name(),
                parser_type=self.get_parser_type(),
                status="SKIPPED",
                warnings=["Carving disabled by configuration (enable_carving=False)"],
            )

        carving_dir = context.scratch_dir / "carving"
        carving_dir.mkdir(parents=True, exist_ok=True)

        layout = context.shared_state.get("tsk_layout")
        volume_offsets = [v.offset for v in layout.volumes] if (layout and getattr(layout, "volumes", None)) else [0]

        carving_result = run_carving(
            image_path=str(context.evidence_path),
            work_dir=str(carving_dir),
            volume_offsets=volume_offsets,
        )
        context.shared_state["carving_result"] = carving_result

        output_files: List[Path] = []
        if carving_result.inventory_csv_path:
            output_files.append(Path(carving_result.inventory_csv_path))

        status = "PARTIAL" if carving_result.warnings else "SUCCESS"
        if not carving_result.attempted:
            status = "SKIPPED"

        return ParserResult(
            parser_name=self.get_parser_name(),
            parser_type=self.get_parser_type(),
            status=status,
            output_files=output_files,
            metrics={
                "unallocated_bytes": carving_result.unallocated_bytes,
                "carved_files": len(carving_result.carved_files),
                "exif_records": len(carving_result.exif_records),
                "keyword_findings": len(carving_result.keyword_findings),
            },
            warnings=carving_result.warnings,
            details={
                "carver": carving_result.carver,
                "unallocated_paths": carving_result.unallocated_paths,
            },
        )


ParserFactory.register("carving", CarvingForensicParser)

