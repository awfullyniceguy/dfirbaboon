"""YARA scanning engine and file header / entropy anomaly detector for dfirbaboon."""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from .base import BaseParser, ParserContext, ParserFactory, ParserResult
    from .tsk_parser import ExtractedFileRecord, tool_timeout
except ImportError:
    from parsers.base import BaseParser, ParserContext, ParserFactory, ParserResult
    from parsers.tsk_parser import ExtractedFileRecord, tool_timeout

try:
    import yara
except ImportError:
    yara = None

logger = logging.getLogger("dfirbaboon.yara_scanner")

BUILTIN_DFIR_YARA_RULES = r"""
rule Suspicious_PowerShell_Encoded_And_Cradle {
    meta:
        description = "Detects suspicious PowerShell download cradles, encoded commands, or AMSI bypass patterns"
        severity = "HIGH"
        mitre_attack = "T1059.001"
    strings:
        $enc1 = "-EncodedCommand" nocase ascii wide
        $enc2 = "FromBase64String" nocase ascii wide
        $cradle1 = "Net.WebClient" nocase ascii wide
        $cradle2 = "DownloadString" nocase ascii wide
        $cradle3 = "Invoke-Expression" nocase ascii wide
        $amsi1 = "AmsiUtils" nocase ascii wide
        $amsi2 = "amsiInitFailed" nocase ascii wide
    condition:
        any of ($enc*) or any of ($cradle*) or any of ($amsi*)
}

rule Credential_Access_Mimikatz_And_LSASS {
    meta:
        description = "Detects Mimikatz commands, LSASS minidump strings, or SAM/NTDS credential harvesting"
        severity = "CRITICAL"
        mitre_attack = "T1003"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase ascii wide
        $m2 = "lsadump::sam" nocase ascii wide
        $m3 = "privilege::debug" nocase ascii wide
        $m4 = "gentilkiwi" nocase ascii wide
        $l1 = "comsvcs.dll" nocase ascii wide
        $l2 = "MiniDumpWriteDump" ascii wide
        $n1 = "ntds.dit" nocase ascii wide
    condition:
        any of ($m*) or ($l1 and $l2) or $n1
}

rule Ransomware_ShadowCopy_Inhibit_System_Recovery {
    meta:
        description = "Detects shadow copy deletion and boot recovery tampering common in ransomware execution"
        severity = "CRITICAL"
        mitre_attack = "T1490"
    strings:
        $s1 = "vssadmin delete shadows" nocase ascii wide
        $s2 = "vssadmin.exe delete shadows" nocase ascii wide
        $s3 = "wmic shadowcopy delete" nocase ascii wide
        $s4 = "bcdedit /set {default} recoveryenabled no" nocase ascii wide
        $s5 = "wbadmin delete catalog" nocase ascii wide
    condition:
        any of them
}

rule Webshell_Execution_Indicators {
    meta:
        description = "Detects common PHP, ASPX, and JSP webshell command execution primitives"
        severity = "HIGH"
        mitre_attack = "T1505.003"
    strings:
        $php1 = "eval(base64_decode(" nocase ascii
        $php2 = "passthru($_" nocase ascii
        $php3 = "shell_exec($_" nocase ascii
        $asp1 = "WScript.Shell" nocase ascii wide
        $cmd1 = "cmd.exe /c " nocase ascii wide
        $sh1  = "/bin/sh -c " ascii
    condition:
        any of ($php*) or ($asp1 and $cmd1) or $sh1
}

rule Persistence_ScheduledTask_And_RunKey {
    meta:
        description = "Detects registry Run key modifications and scheduled task creation artifacts"
        severity = "MEDIUM"
        mitre_attack = "T1053.005, T1547.001"
    strings:
        $reg1 = "CurrentVersion\\Run" nocase ascii wide
        $reg2 = "CurrentVersion\\RunOnce" nocase ascii wide
        $sch1 = "schtasks /create" nocase ascii wide
        $sch2 = "schtasks.exe /create" nocase ascii wide
        $sch3 = "Register-ScheduledTask" nocase ascii wide
        $svc1 = "sc.exe create" nocase ascii wide
    condition:
        any of them
}

rule Suspicious_Packed_UPX_Binary {
    meta:
        description = "Detects UPX-packed PE or ELF binaries often used to obfuscate tooling"
        severity = "MEDIUM"
        mitre_attack = "T1027.002"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_sig = "UPX!" ascii
    condition:
        ($upx0 and $upx1) or $upx_sig
}
"""

MAGIC_SIGNATURES: List[Tuple[bytes, str, Tuple[str, ...]]] = [
    (b"MZ", "Windows PE Executable (MZ)", (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".mui", ".efi")),
    (b"\x7fELF", "Linux ELF Binary", ("", ".elf", ".so", ".bin", ".out", ".ko")),
    (b"ElfFile\x00", "Windows XML Event Log (EVTX)", (".evtx",)),
    (b"regf", "Windows Registry Hive (REGF)", ("", ".dat", ".hiv", ".regtrans-ms", "sam", "system", "software", "security", "ntuser.dat", "amcache.hve")),
    (b"SCCA", "Windows Prefetch (SCCA)", (".pf",)),
    (b"MAM\x04", "Windows 10/11 Compressed Prefetch (MAM)", (".pf",)),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", "Windows Shell Link (LNK)", (".lnk",)),
    (b"%PDF-", "PDF Document", (".pdf",)),
    (b"PK\x03\x04", "ZIP / Office OpenXML / JAR Archive", (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".nupkg")),
]

NON_EXECUTABLE_EXTENSIONS = (
    ".txt",
    ".log",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".csv",
    ".md",
    ".json",
    ".xml",
    ".ini",
    ".cfg",
)


@dataclass
class YaraMatchEntry:
    """Represents a single YARA rule match on an extracted file or raw evidence stream."""

    rule_name: str
    severity: str
    mitre_attack: str
    description: str
    target_path: str
    inode: str
    matched_strings: List[str] = field(default_factory=list)
    file_sha256: str = ""


@dataclass
class HeaderAnomalyEntry:
    """Represents a file header mismatch, double extension, or high-entropy packing anomaly."""

    anomaly_type: str
    severity: str
    target_path: str
    inode: str
    detected_magic: str
    entropy: float
    details: str
    file_sha256: str = ""


@dataclass
class YaraAnalysisResult:
    """Aggregated results from YARA scanning and file header anomaly analysis."""

    rules_loaded: int
    files_scanned: int
    yara_matches: List[YaraMatchEntry] = field(default_factory=list)
    header_anomalies: List[HeaderAnomalyEntry] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class YaraScanner:
    """Compiles YARA signatures and scans extracted forensic artifacts and raw evidence."""

    def __init__(self, custom_rules_dir: Optional[str] = None) -> None:
        self.custom_rules_dir = custom_rules_dir or os.environ.get("YARA_RULES_DIR", "/app/rules")
        self.ruleset_hashes: Dict[str, str] = {}
        self.compiled_rules, self.rules_count = self._compile_rules()

    def _compile_rules(self) -> Tuple[Optional[object], int]:
        """Compile built-in DFIR YARA rules and any custom rules in custom_rules_dir, recording ruleset SHA-256 digests."""
        sources: Dict[str, str] = {"builtin_dfir": BUILTIN_DFIR_YARA_RULES}
        self.ruleset_hashes["builtin_dfir"] = hashlib.sha256(BUILTIN_DFIR_YARA_RULES.encode("utf-8")).hexdigest()
        rules_count = 6

        rules_dir = Path(self.custom_rules_dir)
        if rules_dir.is_dir():
            for rule_file in sorted(rules_dir.glob("*.yar*")):
                try:
                    content = rule_file.read_text(encoding="utf-8", errors="replace")
                    sources[rule_file.stem] = content
                    self.ruleset_hashes[rule_file.name] = hashlib.sha256(content.encode("utf-8")).hexdigest()
                    rules_count += max(1, len(re.findall(r"^\s*rule\s+\w+", content, re.MULTILINE)))
                except OSError as exc:
                    logger.warning("Could not read custom YARA rule %s: %s", rule_file, exc)

        if yara is None:
            logger.warning("yara-python module not installed; using regex fallback for built-in rules.")
            return None, rules_count

        try:
            compiled = yara.compile(sources=sources)
            logger.info("Successfully compiled %d YARA rules across %d namespaces.", rules_count, len(sources))
            return compiled, rules_count
        except Exception as exc:
            logger.error("Failed to compile YARA rules: %s", exc)
            return None, 0

    @staticmethod
    def _compute_sha256_and_entropy(file_path: Path, max_bytes: int = 16 * 1024 * 1024) -> Tuple[str, float, bytes]:
        """Compute SHA-256 hash, Shannon entropy (0.0 - 8.0), and return initial header bytes."""
        sha256_hash = hashlib.sha256()
        byte_counts: Counter[int] = Counter()
        total_counted = 0
        header_bytes = b""

        with file_path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                if not header_bytes:
                    header_bytes = chunk[:64]
                sha256_hash.update(chunk)
                if total_counted < max_bytes:
                    sample = chunk[: max_bytes - total_counted]
                    byte_counts.update(sample)
                    total_counted += len(sample)

        if total_counted == 0:
            return sha256_hash.hexdigest(), 0.0, header_bytes

        entropy = 0.0
        for count in byte_counts.values():
            p_x = count / total_counted
            entropy -= p_x * math.log2(p_x)

        return sha256_hash.hexdigest(), round(entropy, 3), header_bytes

    @staticmethod
    def _detect_magic(header_bytes: bytes) -> Optional[Tuple[str, Tuple[str, ...]]]:
        """Identify known file magic signatures from the first 64 bytes."""
        for magic_bytes, label, expected_exts in MAGIC_SIGNATURES:
            if header_bytes.startswith(magic_bytes):
                return label, expected_exts
        return None

    def _inspect_file_anomalies(
        self,
        local_path: Path,
        logical_path: str,
        inode: str,
        is_deleted: bool,
    ) -> Tuple[str, List[HeaderAnomalyEntry]]:
        """Check file header vs extension mismatches, double extensions, and high entropy."""
        anomalies: List[HeaderAnomalyEntry] = []
        try:
            file_sha256, entropy, header_bytes = self._compute_sha256_and_entropy(local_path)
        except OSError as exc:
            logger.debug("Skipping anomaly check for %s: %s", local_path, exc)
            return "", anomalies

        magic_info = self._detect_magic(header_bytes)
        detected_label = magic_info[0] if magic_info else "Unknown / Raw Data"
        lower_path = logical_path.lower()
        ext = Path(lower_path).suffix

        # 1. Extension masquerading check (e.g., PE MZ or ELF header inside a .txt/.jpg/.pdf/.log file)
        if header_bytes.startswith(b"MZ") and ext in NON_EXECUTABLE_EXTENSIONS:
            anomalies.append(
                HeaderAnomalyEntry(
                    anomaly_type="Masquerading Executable (MZ Header Mismatch)",
                    severity="CRITICAL",
                    target_path=logical_path,
                    inode=inode,
                    detected_magic=detected_label,
                    entropy=entropy,
                    details=f"File has non-executable extension '{ext}' but begins with a Windows PE 'MZ' header.",
                    file_sha256=file_sha256,
                )
            )
        elif header_bytes.startswith(b"\x7fELF") and ext in NON_EXECUTABLE_EXTENSIONS:
            anomalies.append(
                HeaderAnomalyEntry(
                    anomaly_type="Masquerading ELF Binary (Header Mismatch)",
                    severity="CRITICAL",
                    target_path=logical_path,
                    inode=inode,
                    detected_magic=detected_label,
                    entropy=entropy,
                    details=f"File has non-executable extension '{ext}' but begins with an ELF binary header.",
                    file_sha256=file_sha256,
                )
            )

        # 2. Double extension deception (e.g., invoice.pdf.exe, report.docx.scr)
        double_ext_match = re.search(
            r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|bat|ps1|vbs|hta|js|lnk)$",
            lower_path,
        )
        if double_ext_match:
            anomalies.append(
                HeaderAnomalyEntry(
                    anomaly_type="Double Extension Masquerading",
                    severity="HIGH",
                    target_path=logical_path,
                    inode=inode,
                    detected_magic=detected_label,
                    entropy=entropy,
                    details=f"Deceptive double extension detected ({double_ext_match.group(0)}).",
                    file_sha256=file_sha256,
                )
            )

        # 3. High-entropy packed executable or encrypted payload
        if entropy >= 7.25 and (
            header_bytes.startswith(b"MZ")
            or header_bytes.startswith(b"\x7fELF")
            or is_deleted
        ):
            anomalies.append(
                HeaderAnomalyEntry(
                    anomaly_type="High-Entropy Packed / Encrypted Artifact",
                    severity="MEDIUM",
                    target_path=logical_path,
                    inode=inode,
                    detected_magic=detected_label,
                    entropy=entropy,
                    details=f"Shannon entropy is {entropy:.2f}/8.00 bits/byte, indicating packing, compression, or encryption.",
                    file_sha256=file_sha256,
                )
            )

        return file_sha256, anomalies

    def _scan_single_file_yara(
        self,
        local_path: Path,
        logical_path: str,
        inode: str,
        file_sha256: str,
        timeout: int = 60,
    ) -> List[YaraMatchEntry]:
        """Run compiled YARA rules against a single local file (with built-in pattern fallback)."""
        matches_out: List[YaraMatchEntry] = []
        if self.compiled_rules is not None:
            try:
                matches = self.compiled_rules.match(filepath=str(local_path), timeout=timeout)
                for m in matches:
                    meta = getattr(m, "meta", {}) or {}
                    matched_strs: List[str] = []
                    for s in getattr(m, "strings", [])[:8]:
                        identifier = getattr(s, "identifier", str(s))
                        if identifier not in matched_strs:
                            matched_strs.append(identifier)

                    matches_out.append(
                        YaraMatchEntry(
                            rule_name=m.rule,
                            severity=str(meta.get("severity", "HIGH")),
                            mitre_attack=str(meta.get("mitre_attack", "N/A")),
                            description=str(meta.get("description", "YARA signature match")),
                            target_path=logical_path,
                            inode=inode,
                            matched_strings=matched_strs,
                            file_sha256=file_sha256,
                        )
                    )
                return matches_out
            except Exception as exc:
                logger.warning("YARA scan error on %s: %s", local_path, exc)

        # Fallback pattern scanner when yara-python is unavailable in a local test environment
        fallback_rules = [
            (
                "Suspicious_PowerShell_Encoded_And_Cradle",
                "HIGH",
                "T1059.001",
                "Detects suspicious PowerShell download cradles, encoded commands, or AMSI bypass patterns",
                [b"-encodedcommand", b"frombase64string", b"net.webclient", b"downloadstring", b"invoke-expression", b"amsiutils"],
            ),
            (
                "Credential_Access_Mimikatz_And_LSASS",
                "CRITICAL",
                "T1003",
                "Detects Mimikatz commands, LSASS minidump strings, or SAM/NTDS credential harvesting",
                [b"sekurlsa::logonpasswords", b"lsadump::sam", b"privilege::debug", b"gentilkiwi", b"ntds.dit"],
            ),
            (
                "Ransomware_ShadowCopy_Inhibit_System_Recovery",
                "CRITICAL",
                "T1490",
                "Detects shadow copy deletion and boot recovery tampering common in ransomware execution",
                [b"vssadmin delete shadows", b"wmic shadowcopy delete", b"recoveryenabled no", b"wbadmin delete catalog"],
            ),
            (
                "Webshell_Execution_Indicators",
                "HIGH",
                "T1505.003",
                "Detects common PHP, ASPX, and JSP webshell command execution primitives",
                [b"eval(base64_decode(", b"passthru($_", b"shell_exec($_", b"wscript.shell"],
            ),
            (
                "Persistence_ScheduledTask_And_RunKey",
                "MEDIUM",
                "T1053.005, T1547.001",
                "Detects registry Run key modifications and scheduled task creation artifacts",
                [b"currentversion\\run", b"schtasks /create", b"register-scheduledtask", b"sc.exe create"],
            ),
            (
                "Suspicious_Packed_UPX_Binary",
                "MEDIUM",
                "T1027.002",
                "Detects UPX-packed PE or ELF binaries often used to obfuscate tooling",
                [b"upx!"],
            ),
        ]
        try:
            data_lower = local_path.read_bytes()[: 16 * 1024 * 1024].lower()
            for rule_name, severity, mitre, desc, patterns in fallback_rules:
                hits = [p.decode("ascii", errors="ignore") for p in patterns if p in data_lower]
                if hits:
                    matches_out.append(
                        YaraMatchEntry(
                            rule_name=rule_name,
                            severity=severity,
                            mitre_attack=mitre,
                            description=desc,
                            target_path=logical_path,
                            inode=inode,
                            matched_strings=hits,
                            file_sha256=file_sha256,
                        )
                    )
        except OSError as exc:
            logger.debug("Fallback pattern scan skipped for %s: %s", local_path, exc)

        return matches_out

    def scan_artifacts(
        self,
        raw_evidence_path: str,
        extracted_files: List[ExtractedFileRecord],
        raw_evidence_sha256: str = "",
        max_raw_scan_bytes: int = 256 * 1024 * 1024,
        unallocated_paths: Optional[List[str]] = None,
        max_unallocated_scan_bytes: int = 512 * 1024 * 1024 * 1024,
    ) -> YaraAnalysisResult:
        """Scan extracted/carved files, unallocated space, and the raw evidence (unless it is a compressed container)."""
        warnings: List[str] = []
        all_matches: List[YaraMatchEntry] = []
        all_anomalies: List[HeaderAnomalyEntry] = []
        files_scanned = 0

        # 1. Scan all extracted candidate files from TSK icat
        for record in extracted_files:
            local_p = Path(record.local_path)
            if not local_p.is_file():
                continue
            files_scanned += 1
            display_path = (
                f"{record.original_path} (deleted)"
                if record.is_deleted and "(deleted)" not in record.original_path.lower()
                else record.original_path
            )
            f_sha256, anomalies = self._inspect_file_anomalies(
                local_p, display_path, record.inode, record.is_deleted
            )
            all_anomalies.extend(anomalies)
            all_matches.extend(
                self._scan_single_file_yara(local_p, display_path, record.inode, f_sha256)
            )

        # 2. Scan unallocated space (blkls output) where deleted/wiped content lives
        for unalloc_str in unallocated_paths or []:
            unalloc_p = Path(unalloc_str)
            if not unalloc_p.is_file():
                continue
            if unalloc_p.stat().st_size > max_unallocated_scan_bytes:
                warnings.append(
                    f"YARA scan of {unalloc_p.parent.name} unallocated space skipped: "
                    f"{unalloc_p.stat().st_size:,} bytes exceeds the {max_unallocated_scan_bytes:,}-byte cap."
                )
                continue
            files_scanned += 1
            label = f"[unallocated space: {unalloc_p.parent.name}]"
            all_matches.extend(
                self._scan_single_file_yara(
                    unalloc_p, label, "unallocated", "", timeout=tool_timeout()
                )
            )

        # 3. Scan the raw evidence file directly, but never a compressed container (EWF/AFF),
        #    where signatures and entropy of the compressed bytes are meaningless.
        raw_path = Path(raw_evidence_path)
        if raw_path.is_file():
            with raw_path.open("rb") as raw_handle:
                raw_head = raw_handle.read(8)
            is_container = raw_head.startswith((b"EVF", b"AFF", b"SMART")) or raw_path.suffix.lower() in (
                ".e01", ".ex01", ".s01", ".aff", ".afd", ".vmdk", ".vhd", ".vhdx",
            )
            raw_size = raw_path.stat().st_size
            if is_container:
                logger.info("Skipping direct scan of container-format evidence %s", raw_path.name)
            elif raw_size <= max_raw_scan_bytes or not extracted_files:
                files_scanned += 1
                f_sha256, anomalies = self._inspect_file_anomalies(
                    raw_path, raw_path.name, "raw-image", False
                )
                effective_sha256 = raw_evidence_sha256 or f_sha256
                all_anomalies.extend(anomalies)
                if raw_size <= max_raw_scan_bytes:
                    all_matches.extend(
                        self._scan_single_file_yara(
                            raw_path, raw_path.name, "raw-image", effective_sha256
                        )
                    )

        logger.info(
            "Completed YARA & anomaly scan over %d files: %d YARA matches, %d header/entropy anomalies.",
            files_scanned,
            len(all_matches),
            len(all_anomalies),
        )
        return YaraAnalysisResult(
            rules_loaded=self.rules_count,
            files_scanned=files_scanned,
            yara_matches=all_matches,
            header_anomalies=all_anomalies,
            warnings=warnings,
        )


class YaraForensicParser(BaseParser):
    """ForensicParser plugin implementation for YARA rule matching and entropy / header anomaly analysis."""

    def get_parser_name(self) -> str:
        return "yara"

    def get_parser_type(self) -> str:
        return "scanner"

    def validate(self, evidence_path: Path) -> bool:
        return evidence_path.is_file() and evidence_path.stat().st_size > 0

    def parse(self, context: ParserContext) -> ParserResult:
        if not context.config.enable_yara:
            return ParserResult(
                parser_name=self.get_parser_name(),
                parser_type=self.get_parser_type(),
                status="SKIPPED",
                warnings=["YARA scanning disabled by configuration (enable_yara=False)"],
            )

        scanner = YaraScanner()
        context.shared_state["yara_ruleset_hashes"] = scanner.ruleset_hashes

        tsk_analysis = context.shared_state.get("tsk_analysis")
        extracted_files = tsk_analysis.extracted_files if tsk_analysis else []

        carving_result = context.shared_state.get("carving_result")
        unallocated_paths = carving_result.unallocated_paths if carving_result else []
        carved_files_dir = context.scratch_dir / "carving"

        yara_result = scanner.scan_forensic_targets(
            extracted_files=extracted_files,
            raw_evidence_path=str(context.evidence_path),
            raw_evidence_sha256=context.shared_state.get("sha256", ""),
            carved_files_dir=str(carved_files_dir) if carved_files_dir.exists() else None,
            unallocated_paths=[str(p) for p in unallocated_paths],
        )
        context.shared_state["yara_result"] = yara_result

        status = "PARTIAL" if yara_result.warnings else "SUCCESS"
        return ParserResult(
            parser_name=self.get_parser_name(),
            parser_type=self.get_parser_type(),
            status=status,
            metrics={
                "rules_loaded": yara_result.rules_loaded,
                "files_scanned": yara_result.files_scanned,
                "yara_matches": len(yara_result.yara_matches),
                "header_anomalies": len(yara_result.header_anomalies),
            },
            warnings=yara_result.warnings,
            details={
                "ruleset_hashes": scanner.ruleset_hashes,
                "matches": [m.rule_name for m in yara_result.yara_matches],
            },
        )


ParserFactory.register("yara", YaraForensicParser)

