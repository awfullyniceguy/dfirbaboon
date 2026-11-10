"""The Sleuth Kit (TSK) wrappers for partition layout, filesystem metadata, deleted file recovery, icat extraction, and mactime supertimelines.

Designed for very large (200 GB+) server images: every partition with a recognizable file system is processed,
independent phases run in parallel, long-running output is streamed instead of buffered, tool timeouts are
configurable (DFIR_TOOL_TIMEOUT_SEC), and any degradation is reported as an explicit warning instead of being hidden.
"""

from __future__ import annotations

import csv
import logging
import os
import re
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

try:
    from parsers.base import BaseParser, ParserContext, ParserFactory, ParserResult
except ImportError:
    from worker.parsers.base import BaseParser, ParserContext, ParserFactory, ParserResult

try:
    import pytsk3
except ImportError:
    pytsk3 = None

logger = logging.getLogger("dfirbaboon.tsk_parser")

HIGH_SIGNAL_EXTENSIONS = (
    ".exe", ".dll", ".ps1", ".bat", ".vbs", ".lnk", ".pf", ".evtx", ".sys", ".scr",
    ".hta", ".js", ".cmd", ".msi", ".jar", ".sh", ".elf",
)

HIGH_SIGNAL_PATH_PATTERNS = (
    "/users/", "/documents and settings/", "/home/", "/root/", "/appdata/", "/programdata/",
    "/temp/", "/tmp/", "/windows/system32/tasks/", "/windows/tasks/", "/windows/prefetch/",
    "/windows/system32/winevt/logs/", "start menu/programs/startup",
)

IGNORED_PARTITION_KEYWORDS = (
    "unallocated", "meta", "primary table", "gpt header", "partition table", "safety table",
    "extended", "microsoft reserved",
)

DEFAULT_TOOL_TIMEOUT_SEC = 6 * 3600
MAX_DELETED_ENTRIES = 100000
RAW_OUTPUT_CAP_CHARS = 20000


def tool_timeout(default: int = DEFAULT_TOOL_TIMEOUT_SEC) -> int:
    """Per-tool timeout in seconds (DFIR_TOOL_TIMEOUT_SEC overrides the default)."""
    try:
        return int(os.environ.get("DFIR_TOOL_TIMEOUT_SEC", default))
    except ValueError:
        return default


@dataclass
class PartitionEntry:
    """Represents a single row parsed from mmls output."""

    slot: str
    start_sector: int
    end_sector: int
    length_sectors: int
    description: str


@dataclass
class VolumeInfo:
    """A partition (or whole-image volume) that carries a recognizable file system."""

    index: int
    offset: int
    description: str
    length_sectors: int
    fsstat_raw: str

    def prefix(self, multi: bool) -> str:
        """Path prefix applied to every entry from this volume when the image has several volumes."""
        return f"vol{self.index}" if multi else ""


@dataclass
class DeletedFileEntry:
    """Represents a deleted file or unlinked inode discovered by fls."""

    inode: str
    file_type: str
    path: str
    reallocated: bool


@dataclass
class TimelineEvent:
    """Represents a high-signal row from the mactime CSV timeline."""

    date: str
    size: str
    macb: str
    perms: str
    uid: str
    gid: str
    inode: str
    file_name: str
    reason: str


@dataclass
class ExtractedFileRecord:
    """Metadata for a file carved from the disk image via icat."""

    inode: str
    original_path: str
    local_path: str
    size_bytes: int
    is_deleted: bool


@dataclass
class TSKLayout:
    """Result of partition / file system discovery."""

    tsk_version: str
    primary_offset: int
    mmls_raw: str
    partitions: List[PartitionEntry]
    volumes: List[VolumeInfo]

    @property
    def is_disk_image(self) -> bool:
        return bool(self.volumes)


@dataclass
class TSKAnalysisResult:
    """Aggregated forensic findings from The Sleuth Kit."""

    tsk_version: str
    primary_offset: int
    is_disk_image: bool
    mmls_raw: str
    partitions: List[PartitionEntry] = field(default_factory=list)
    volumes: List[VolumeInfo] = field(default_factory=list)
    fsstat_raw: str = ""
    fls_deleted_raw: str = ""
    deleted_files: List[DeletedFileEntry] = field(default_factory=list)
    timeline_csv_path: str = ""
    total_timeline_events: int = 0
    high_risk_timeline_events: List[TimelineEvent] = field(default_factory=list)
    extracted_files: List[ExtractedFileRecord] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class TSKParser:
    """Executes The Sleuth Kit CLI tools and parses forensic outputs."""

    def __init__(self, image_path: str, work_dir: str) -> None:
        self.image_path = str(Path(image_path).resolve())
        self.work_dir = Path(work_dir).resolve()
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.extracted_dir = self.work_dir / "extracted"
        self.extracted_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------ subprocess helpers
    @staticmethod
    def _run_cmd(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """Run a short subprocess command and return (returncode, stdout, stderr)."""
        timeout = timeout or tool_timeout()
        logger.info("Executing command: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace", timeout=timeout, check=False
            )
            return proc.returncode, proc.stdout, proc.stderr
        except FileNotFoundError as exc:
            logger.error("Binary not found while executing %s: %s", cmd[0], exc)
            return 127, "", str(exc)
        except subprocess.TimeoutExpired as exc:
            logger.error("Command timed out after %d seconds: %s", timeout, " ".join(cmd))
            out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            return 124, out, f"Command timed out after {timeout}s"

    @staticmethod
    def _stream_cmd(
        cmd: List[str],
        on_line: Callable[[str], bool],
        timeout: Optional[int] = None,
    ) -> Tuple[int, str, bool, bool]:
        """Stream a command's stdout line by line (constant memory).

        `on_line` returns True to stop early. Returns (returncode, stderr, timed_out, stopped_early).
        """
        timeout = timeout or tool_timeout()
        logger.info("Streaming command: %s", " ".join(cmd))
        stderr_file = tempfile.TemporaryFile()
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=stderr_file, text=True, errors="replace", bufsize=1 << 20
            )
        except FileNotFoundError as exc:
            stderr_file.close()
            return 127, str(exc), False, False

        state = {"timed_out": False}

        def _kill() -> None:
            state["timed_out"] = True
            proc.kill()

        timer = threading.Timer(timeout, _kill)
        timer.start()
        stopped_early = False
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if on_line(line.rstrip("\n")):
                    stopped_early = True
                    proc.kill()
                    break
        finally:
            timer.cancel()
        proc.wait()
        stderr_file.seek(0)
        err = stderr_file.read().decode("utf-8", errors="replace")[:2000]
        stderr_file.close()
        return proc.returncode, err, state["timed_out"], stopped_early

    def get_tsk_version(self) -> str:
        """Retrieve The Sleuth Kit version via fls -V or pytsk3."""
        rc, stdout, stderr = self._run_cmd(["fls", "-V"], timeout=30)
        if rc == 0 and stdout.strip():
            return stdout.strip().splitlines()[0]
        if pytsk3 is not None:
            try:
                return f"pytsk3/{pytsk3.TSK_VERSION_STR}"
            except AttributeError:
                return "pytsk3-installed"
        return f"tsk-unknown ({stderr.strip() or 'unavailable'})"

    # --------------------------------------------------------------------- layout
    def run_mmls(self) -> Tuple[int, str, List[PartitionEntry], List[PartitionEntry]]:
        """Run mmls; return (primary_offset, raw_output, all_partitions, candidate_data_partitions)."""
        rc, stdout, stderr = self._run_cmd(["mmls", self.image_path], timeout=600)
        if rc != 0 or not stdout.strip():
            msg = (
                stdout.strip()
                or stderr.strip()
                or "No partition table detected (logical filesystem or standalone artifact). Using offset 0."
            )
            logger.info("mmls returned code %d; falling back to sector offset 0.", rc)
            return 0, msg, [], []

        partitions: List[PartitionEntry] = []
        line_re = re.compile(r"^\s*\d+:\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$")
        for line in stdout.splitlines():
            match = line_re.match(line)
            if not match:
                continue
            slot, start_str, end_str, length_str, desc = match.groups()
            partitions.append(
                PartitionEntry(slot, int(start_str), int(end_str), int(length_str), desc.strip())
            )

        candidates = [
            p
            for p in partitions
            if p.slot.lower() != "meta"
            and not any(ignored in p.description.lower() for ignored in IGNORED_PARTITION_KEYWORDS)
        ]
        if not candidates:
            return 0, stdout.strip(), partitions, []

        non_efi = [p for p in candidates if "efi system" not in p.description.lower()]
        primary = max(non_efi or candidates, key=lambda p: p.length_sectors)
        logger.info(
            "mmls found %d candidate partitions; primary at sector %d (%s, %d sectors)",
            len(candidates), primary.start_sector, primary.description, primary.length_sectors,
        )
        return primary.start_sector, stdout.strip(), partitions, candidates

    def run_fsstat(self, offset: int) -> Tuple[bool, str]:
        """Run fsstat -o <offset> <image>; returns (success, output_or_error)."""
        rc, stdout, stderr = self._run_cmd(["fsstat", "-o", str(offset), self.image_path], timeout=900)
        if rc == 0 and stdout.strip():
            return True, stdout.strip()
        return False, ((stdout + "\n" + stderr).strip() or "Filesystem metadata unavailable (non-filesystem artifact).")

    def detect_layout(self) -> TSKLayout:
        """Discover every partition carrying a file system (not only the largest)."""
        tsk_version = self.get_tsk_version()
        primary_offset, mmls_raw, partitions, candidates = self.run_mmls()

        volumes: List[VolumeInfo] = []
        tried: set = set()
        for part in sorted(candidates, key=lambda p: p.start_sector):
            tried.add(part.start_sector)
            ok, raw = self.run_fsstat(part.start_sector)
            if ok:
                volumes.append(
                    VolumeInfo(len(volumes), part.start_sector, part.description, part.length_sectors, raw)
                )
            else:
                logger.info("No file system at sector %d (%s); skipping.", part.start_sector, part.description)

        if not volumes and 0 not in tried:
            ok, raw = self.run_fsstat(0)
            if ok:
                volumes.append(VolumeInfo(0, 0, "Unpartitioned / logical volume", 0, raw))

        if volumes:
            primary = max(volumes, key=lambda v: v.length_sectors)
            primary_offset = primary.offset
        return TSKLayout(tsk_version, primary_offset, mmls_raw, partitions, volumes)

    # ------------------------------------------------------------------ phases
    def _volume_deleted(self, vol: VolumeInfo, multi: bool) -> Tuple[str, List[DeletedFileEntry], List[str]]:
        """Stream `fls -r -d -p -o <offset>` and parse deleted entries with constant memory."""
        warnings: List[str] = []
        entries: List[DeletedFileEntry] = []
        raw_lines: List[str] = []
        raw_chars = 0
        fls_re = re.compile(r"^([a-z\-/]+)\s+\*\s+([^\s:]+?)(?:\(realloc\))?:\s+(.+)$", re.IGNORECASE)
        prefix = vol.prefix(multi)
        counters = {"total": 0}

        def on_line(line: str) -> bool:
            nonlocal raw_chars
            stripped = line.strip()
            if not stripped:
                return False
            counters["total"] += 1
            if raw_chars < RAW_OUTPUT_CAP_CHARS:
                raw_lines.append(stripped)
                raw_chars += len(stripped) + 1
            match = fls_re.match(stripped)
            if match and len(entries) < MAX_DELETED_ENTRIES:
                ftype, inode, fpath = match.groups()
                entries.append(
                    DeletedFileEntry(
                        inode.strip(), ftype.strip(),
                        f"{prefix}/{fpath.strip()}" if prefix else fpath.strip(),
                        "(realloc)" in stripped,
                    )
                )
            return False

        rc, err, timed_out, _ = self._stream_cmd(
            ["fls", "-r", "-d", "-p", "-o", str(vol.offset), self.image_path], on_line
        )
        if timed_out:
            warnings.append(f"Deleted-file listing (fls -d) for volume @{vol.offset} timed out; results are partial.")
        elif rc != 0 and not entries:
            warnings.append(f"fls -d failed for volume @{vol.offset} (rc={rc}): {err.strip()[:200]}")
        if counters["total"] > MAX_DELETED_ENTRIES:
            warnings.append(
                f"Volume @{vol.offset}: {counters['total']:,} deleted entries found; only the first {MAX_DELETED_ENTRIES:,} are parsed."
            )
        raw = "\n".join(raw_lines)
        if multi:
            raw = f"# Volume {vol.index} @ sector {vol.offset} ({vol.description})\n{raw}"
        return raw, entries, warnings

    def _volume_bodyfile(self, vol: VolumeInfo, multi: bool, dest: Path) -> Tuple[bool, str]:
        """Write `fls -r -m <prefix> -o <offset>` bodyfile for one volume."""
        mount = f"/{vol.prefix(multi)}" if multi else "/"
        logger.info("Generating TSK bodyfile for volume %d at %s", vol.index, dest)
        try:
            with dest.open("w", encoding="utf-8", errors="replace") as out:
                proc = subprocess.run(
                    ["fls", "-r", "-m", mount, "-o", str(vol.offset), self.image_path],
                    stdout=out, stderr=subprocess.PIPE, text=True, errors="replace",
                    timeout=tool_timeout(), check=False,
                )
        except subprocess.TimeoutExpired:
            return False, f"Bodyfile generation (fls -m) for volume @{vol.offset} timed out; timeline is partial."
        except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
            return False, f"Bodyfile generation failed for volume @{vol.offset}: {exc}"
        if proc.returncode != 0:
            return False, f"fls -m returned {proc.returncode} for volume @{vol.offset}: {proc.stderr.strip()[:200]}"
        return True, ""

    def _synthetic_timeline(self, csv_path: Path) -> None:
        """Single-row timeline for standalone artifacts that are not file systems."""
        stat_info = os.stat(self.image_path)
        img_name = Path(self.image_path).name
        bodyfile = self.work_dir / "bodyfile.txt"
        bodyfile.write_text(
            f"0|/{img_name}|0|-rwxr-xr-x|0|0|{stat_info.st_size}|"
            f"{int(stat_info.st_atime)}|{int(stat_info.st_mtime)}|{int(stat_info.st_ctime)}|{int(stat_info.st_ctime)}\n",
            encoding="utf-8",
        )
        rc, _out, _err = 0, "", ""
        try:
            with csv_path.open("w", encoding="utf-8", errors="replace") as csv_out:
                proc = subprocess.run(
                    ["mactime", "-b", str(bodyfile), "-d"], stdout=csv_out, stderr=subprocess.PIPE,
                    text=True, timeout=300, check=False,
                )
                rc = proc.returncode
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            rc = 127
        if rc != 0 or csv_path.stat().st_size == 0:
            csv_path.write_text(
                "Date,Size,Type,Mode,UID,GID,Meta,File Name\n"
                f"1970-01-01T00:00:00Z,{stat_info.st_size},macb,-rwxr-xr-x,0,0,0,/{img_name}\n",
                encoding="utf-8",
            )

    def _run_mactime(self, bodyfile: Path, csv_path: Path) -> Tuple[bool, str]:
        logger.info("Running mactime over %s -> %s", bodyfile, csv_path)
        try:
            with csv_path.open("w", encoding="utf-8", errors="replace") as csv_out:
                proc = subprocess.run(
                    ["mactime", "-b", str(bodyfile), "-d"], stdout=csv_out, stderr=subprocess.PIPE,
                    text=True, errors="replace", timeout=tool_timeout(), check=False,
                )
        except subprocess.TimeoutExpired:
            return False, "mactime timed out; supertimeline CSV is partial."
        except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
            return False, f"mactime failed: {exc}"
        if proc.returncode != 0:
            return False, f"mactime returned {proc.returncode}: {proc.stderr.strip()[:200]}"
        return True, ""

    @staticmethod
    def _classify_high_signal(file_name: str) -> Optional[str]:
        """Determine if a file path in the timeline represents a high-signal forensic artifact."""
        lower_name = file_name.lower()
        clean_name = re.sub(r"\s*\(deleted.*?\)\s*$", "", lower_name).strip()

        matched_reasons: List[str] = []
        for ext in HIGH_SIGNAL_EXTENSIONS:
            if clean_name.endswith(ext) or f"{ext}:" in clean_name:
                matched_reasons.append(f"Artifact({ext})")
                break
        for pattern in HIGH_SIGNAL_PATH_PATTERNS:
            if pattern in lower_name:
                matched_reasons.append(f"Path({pattern.strip('/')})")
                break
        if "(deleted)" in lower_name and matched_reasons:
            matched_reasons.append("Deleted")
        return ", ".join(matched_reasons) if matched_reasons else None

    def _filter_high_signal_timeline(self, csv_path: Path, max_events: int = 500) -> Tuple[int, List[TimelineEvent]]:
        """Stream the mactime CSV and keep high-signal DFIR events."""
        total_events = 0
        high_risk_events: List[TimelineEvent] = []
        with csv_path.open("r", encoding="utf-8", errors="replace") as handle:
            reader = csv.reader(handle)
            for idx, row in enumerate(reader):
                if idx == 0 and row and row[0].strip().lower() == "date":
                    continue
                if len(row) < 8:
                    continue
                total_events += 1
                if len(high_risk_events) >= max_events:
                    continue
                file_name_val = ",".join(row[7:]).strip()
                reason = self._classify_high_signal(file_name_val)
                if reason:
                    high_risk_events.append(
                        TimelineEvent(
                            row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip(),
                            row[4].strip(), row[5].strip(), row[6].strip(), file_name_val, reason,
                        )
                    )
        logger.info("Parsed %d timeline rows; %d high-signal events.", total_events, len(high_risk_events))
        return total_events, high_risk_events

    def _volume_extract(
        self, vol: VolumeInfo, multi: bool, max_files: int = 150, max_file_size_bytes: int = 50 * 1024 * 1024
    ) -> List[ExtractedFileRecord]:
        """Extract high-interest files with icat. Stops listing as soon as enough candidates are found."""
        line_re = re.compile(r"^([a-z\-/]+)\s+(\*\s+)?([^\s:]+?)(?:\(realloc\))?:\s+(.+)$", re.IGNORECASE)
        prefix = vol.prefix(multi)
        candidates: List[Tuple[str, str, bool]] = []

        def on_line(line: str) -> bool:
            match = line_re.match(line.strip())
            if not match:
                return False
            _ftype, deleted_marker, inode, fpath = match.groups()
            fpath_clean = fpath.strip()
            is_deleted = bool(deleted_marker)
            if self._classify_high_signal(fpath_clean) is not None or is_deleted:
                candidates.append((inode.strip(), f"{prefix}/{fpath_clean}" if prefix else fpath_clean, is_deleted))
            return len(candidates) >= max_files

        self._stream_cmd(["fls", "-r", "-F", "-p", "-o", str(vol.offset), self.image_path], on_line)

        extracted: List[ExtractedFileRecord] = []
        vol_dir = self.extracted_dir / f"vol{vol.index}"
        vol_dir.mkdir(parents=True, exist_ok=True)
        for idx, (inode, fpath, is_deleted) in enumerate(candidates[:max_files]):
            safe_base = re.sub(r"[^A-Za-z0-9._-]", "_", Path(fpath).name)[:80]
            safe_inode = re.sub(r"[^A-Za-z0-9._-]", "_", inode)
            dest_file = vol_dir / f"{idx:04d}_inode_{safe_inode}_{safe_base}"
            try:
                with dest_file.open("wb") as out_f:
                    proc = subprocess.run(
                        ["icat", "-o", str(vol.offset), self.image_path, inode],
                        stdout=out_f, stderr=subprocess.PIPE, timeout=300, check=False,
                    )
                fsize = dest_file.stat().st_size if dest_file.exists() else 0
                if proc.returncode == 0 and 0 < fsize <= max_file_size_bytes:
                    extracted.append(ExtractedFileRecord(inode, fpath, str(dest_file), fsize, is_deleted))
                else:
                    dest_file.unlink(missing_ok=True)
            except (OSError, subprocess.SubprocessError) as exc:
                logger.debug("Failed to extract inode %s (%s): %s", inode, fpath, exc)
                dest_file.unlink(missing_ok=True)
        logger.info("Volume %d: extracted %d candidate files via icat.", vol.index, len(extracted))
        return extracted

    # -------------------------------------------------------------- orchestration
    def analyze_filesystem(self, layout: TSKLayout, timeline_csv_path: str) -> TSKAnalysisResult:
        """Run all file system phases for every volume; independent phases execute in parallel."""
        csv_path = Path(timeline_csv_path)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        result = TSKAnalysisResult(
            tsk_version=layout.tsk_version,
            primary_offset=layout.primary_offset,
            is_disk_image=layout.is_disk_image,
            mmls_raw=layout.mmls_raw,
            partitions=layout.partitions,
            volumes=layout.volumes,
            timeline_csv_path=timeline_csv_path,
        )

        if not layout.volumes:
            result.fsstat_raw = "Filesystem metadata unavailable (non-filesystem artifact)."
            self._synthetic_timeline(csv_path)
            result.total_timeline_events, result.high_risk_timeline_events = self._filter_high_signal_timeline(csv_path)
            return result

        multi = len(layout.volumes) > 1
        sections = []
        for vol in layout.volumes:
            header = f"# Volume {vol.index} @ sector {vol.offset} ({vol.description})\n" if multi else ""
            sections.append(header + vol.fsstat_raw)
        result.fsstat_raw = "\n\n".join(sections)

        workers = max(3, min(12, len(layout.volumes) * 3))
        body_paths: Dict[int, Path] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            body_futs = {}
            for vol in layout.volumes:
                body_paths[vol.index] = self.work_dir / f"bodyfile_vol{vol.index}.txt"
                body_futs[vol.index] = pool.submit(self._volume_bodyfile, vol, multi, body_paths[vol.index])
            del_futs = {vol.index: pool.submit(self._volume_deleted, vol, multi) for vol in layout.volumes}
            ext_futs = {vol.index: pool.submit(self._volume_extract, vol, multi) for vol in layout.volumes}

            # mactime starts as soon as the bodyfiles are ready, while other phases still run.
            for idx, fut in body_futs.items():
                ok, msg = fut.result()
                if not ok:
                    result.warnings.append(msg)

            combined = self.work_dir / "bodyfile.txt"
            with combined.open("w", encoding="utf-8", errors="replace") as out:
                for vol in layout.volumes:
                    bp = body_paths[vol.index]
                    if bp.exists():
                        with bp.open("r", encoding="utf-8", errors="replace") as src:
                            for chunk in iter(lambda: src.read(16 * 1024 * 1024), ""):
                                out.write(chunk)
            if combined.stat().st_size == 0:
                result.warnings.append("TSK bodyfile is empty; no timeline could be generated.")
                csv_path.write_text("Date,Size,Type,Mode,UID,GID,Meta,File Name\n", encoding="utf-8")
            else:
                ok, msg = self._run_mactime(combined, csv_path)
                if not ok:
                    result.warnings.append(msg)
            result.total_timeline_events, result.high_risk_timeline_events = self._filter_high_signal_timeline(csv_path)

            raw_parts: List[str] = []
            for idx, fut in del_futs.items():
                try:
                    raw, entries, warns = fut.result()
                    raw_parts.append(raw)
                    result.deleted_files.extend(entries)
                    result.warnings.extend(warns)
                except Exception as exc:  # noqa: BLE001 - recorded as an explicit warning
                    result.warnings.append(f"Deleted-file phase crashed for volume {idx}: {exc}")
            result.fls_deleted_raw = "\n\n".join(p for p in raw_parts if p)

            for idx, fut in ext_futs.items():
                try:
                    result.extracted_files.extend(fut.result())
                except Exception as exc:  # noqa: BLE001
                    result.warnings.append(f"File extraction phase crashed for volume {idx}: {exc}")

        return result

    def execute_full_analysis(self, timeline_csv_path: str) -> TSKAnalysisResult:
        """Execute end-to-end Sleuth Kit analysis over the target image or artifact."""
        return self.analyze_filesystem(self.detect_layout(), timeline_csv_path)


class TSKForensicParser(BaseParser):
    """ForensicParser plugin implementation wrapping The Sleuth Kit."""

    def get_parser_name(self) -> str:
        return "tsk"

    def get_parser_type(self) -> str:
        return "filesystem"

    def validate(self, evidence_path: Path) -> bool:
        return evidence_path.is_file() and evidence_path.stat().st_size > 0

    def parse(self, context: ParserContext) -> ParserResult:
        tsk_work_dir = context.scratch_dir / "tsk"
        tsk_work_dir.mkdir(parents=True, exist_ok=True)
        timeline_csv_path = context.scratch_dir / "timelines" / "mactime_supertimeline.csv"
        timeline_csv_path.parent.mkdir(parents=True, exist_ok=True)

        engine = TSKParser(image_path=str(context.evidence_path), work_dir=str(tsk_work_dir))
        layout = engine.detect_layout()
        context.shared_state["tsk_layout"] = layout

        analysis = engine.analyze_filesystem(layout, str(timeline_csv_path))
        context.shared_state["tsk_analysis"] = analysis

        output_files: List[Path] = [timeline_csv_path]
        for f in analysis.extracted_files:
            output_files.append(Path(f.local_path))

        status = "PARTIAL" if analysis.warnings else "SUCCESS"
        if not analysis.is_disk_image and not analysis.total_timeline_events:
            status = "FAILED" if analysis.warnings else "PARTIAL"

        return ParserResult(
            parser_name=self.get_parser_name(),
            parser_type=self.get_parser_type(),
            status=status,
            output_files=output_files,
            metrics={
                "volumes": len(layout.volumes),
                "total_timeline_events": analysis.total_timeline_events,
                "high_risk_timeline_events": len(analysis.high_risk_timeline_events),
                "deleted_files": len(analysis.deleted_files),
                "extracted_files": len(analysis.extracted_files),
            },
            warnings=analysis.warnings,
            details={
                "tsk_version": analysis.tsk_version,
                "is_disk_image": analysis.is_disk_image,
                "volumes": [(v.offset, v.description) for v in layout.volumes],
            },
        )


ParserFactory.register("tsk", TSKForensicParser)

