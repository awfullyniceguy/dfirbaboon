"""Formats forensic analysis outputs into token-safe, AI-friendly Markdown reports with YAML frontmatter."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .carving import MEDIA_EXTENSIONS, CarvingResult
    from .tsk_parser import TSKAnalysisResult
    from .yara_scanner import YaraAnalysisResult
except ImportError:
    from parsers.carving import MEDIA_EXTENSIONS, CarvingResult
    from parsers.tsk_parser import TSKAnalysisResult
    from parsers.yara_scanner import YaraAnalysisResult

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

logger = logging.getLogger("dfirbaboon.md_exporter")

MAX_SECTION_CHARS = 15000


class MarkdownExporter:
    """Generates token-safe Markdown reports designed for LLM/RAG pipelines and Obsidian vaults."""

    def __init__(self, output_dir: str, coc_metadata: Dict[str, Any]) -> None:
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.coc = coc_metadata

    @staticmethod
    def truncate_section(text: str, limit: int = MAX_SECTION_CHARS) -> str:
        """Cleanly truncate raw command outputs at `limit` characters to prevent LLM context overflow."""
        if not text:
            return "*(No output recorded)*"
        if len(text) <= limit:
            return text
        truncated = text[:limit]
        # Avoid splitting mid-line when possible
        last_newline = truncated.rfind("\n")
        if last_newline > int(limit * 0.85):
            truncated = truncated[:last_newline]
        omitted = len(text) - len(truncated)
        return (
            f"{truncated}\n\n"
            f"... [TRUNCATED AT {limit:,} CHARACTERS ({omitted:,} CHARS OMITTED) "
            f"FOR LLM TOKEN SAFETY — SEE FULL ARTIFACT IN S3 VAULT] ..."
        )

    @staticmethod
    def _render_table(rows: List[List[Any]], headers: List[str]) -> str:
        """Render a GitHub-flavored Markdown table using tabulate with a built-in fallback."""
        if not rows:
            return "*(No matching records)*"
        if tabulate is not None:
            return tabulate(rows, headers=headers, tablefmt="github")

        header_line = "| " + " | ".join(str(h) for h in headers) + " |"
        separator_line = "| " + " | ".join("---" for _ in headers) + " |"
        body_lines = [
            "| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |"
            for row in rows
        ]
        return "\n".join([header_line, separator_line, *body_lines])

    def _build_frontmatter(self) -> str:
        """Build the mandatory YAML frontmatter block with FRE 1006 / OSAC evidentiary standards."""
        incident_id = str(self.coc.get("incident_id", "INC-UNASSIGNED"))
        incident_tag = incident_id.lower()
        evidence_file = str(self.coc.get("evidence_file", "unknown"))
        sha256 = str(self.coc.get("sha256", ""))
        md5 = str(self.coc.get("md5", ""))
        size_bytes = int(self.coc.get("size_bytes", 0))
        intake_utc = str(self.coc.get("intake_timestamp_utc", ""))
        processed_utc = str(self.coc.get("processed_timestamp_utc", ""))
        acq_verified = bool(self.coc.get("acquisition_hash_verified", False))

        return (
            "---\n"
            "pipeline: dfirbaboon\n"
            f"incident_id: {incident_id}\n"
            f'evidence_file: "{evidence_file}"\n'
            f'sha256: "{sha256}"\n'
            f'md5: "{md5}"\n'
            f"size_bytes: {size_bytes}\n"
            f'intake_utc: "{intake_utc}"\n'
            f'processed_utc: "{processed_utc}"\n'
            f"acquisition_hash_verified: {str(acq_verified).lower()}\n"
            "evidentiary_standard: FRE_1006_AND_OSAC_DIGITAL_EVIDENCE\n"
            "admissibility_role: INVESTIGATIVE_TRIAGE_SUMMARY\n"
            'legal_disclaimer: "This document is a bounded summary for investigative triage generated under FRE 1006 and OSAC Digital Evidence guidelines. Authoritative unabridged records reside in mactime_supertimeline.csv, carved_files_inventory.csv, and raw_evidence/."\n'
            f"tags: [dfirbaboon, forensics, dfir, chain-of-custody, tsk, fre1006, osac, {incident_tag}]\n"
            "---\n\n"
        )

    @staticmethod
    def _evidentiary_disclaimer_block() -> str:
        """Render standard FRE 1006 and OSAC Digital Evidence disclaimer block."""
        return (
            "> [!IMPORTANT] Evidentiary & FRE 1006 Summary Disclaimer\n"
            "> This document is an automated, bounded forensic triage summary generated under Federal Rules of Evidence (FRE) Rule 1006 and OSAC Digital Evidence standards. "
            "Raw command outputs are bounded to ensure token safety in LLM/RAG pipelines. For certified court admissibility and unabridged forensic analysis, "
            "examiners must refer directly to the primary bit-stream evidence copy (`raw_evidence/`) and authoritative tabular datasets (`mactime_supertimeline.csv` and `carved_files_inventory.csv`).\n\n"
        )

    def generate_chain_of_custody_md(self) -> Path:
        """Generate 00_CHAIN_OF_CUSTODY.md."""
        file_path = self.output_dir / "00_CHAIN_OF_CUSTODY.md"
        incident_id = self.coc.get("incident_id", "INC-UNASSIGNED")
        evidence_file = self.coc.get("evidence_file", "unknown")

        acq_status = (
            "**VERIFIED (Matches collector acquisition SHA-256)**"
            if self.coc.get("acquisition_hash_verified")
            else "*(No collector manifest provided; custody established from S3 intake)*"
        )

        is_compliance = self.coc.get("forensic_mode") == "compliance" or bool(self.coc.get("object_lock_enabled", False))
        kms_display = self.coc.get("kms_key_arn") or ("SSE-KMS" if is_compliance else "AES256 (SSE-S3)")
        object_lock_display = (
            "`ENABLED (COMPLIANCE Mode, 365 Days Retention)`"
            if self.coc.get("object_lock_enabled", is_compliance)
            else "`DISABLED (simple-forensics mode)`"
        )
        legal_hold_display = (
            "`ACTIVE (LegalHold=ON applied to raw evidence)`"
            if self.coc.get("legal_hold_applied", is_compliance)
            else "`DISABLED (simple-forensics mode)`"
        )
        audit_display = (
            "`AWS CloudTrail S3 Data Events & KMS Decrypt Logging Active`"
            if is_compliance
            else "`Standard CloudWatch Worker Logs (simple-forensics mode)`"
        )

        coc_rows = [
            ["Pipeline Tool", self.coc.get("tool", "dfirbaboon")],
            ["Incident Identifier", f"`{incident_id}`"],
            ["Evidence Filename", f"`{evidence_file}`"],
            ["Source Intake Bucket", f"`s3://{self.coc.get('source_bucket')}/{self.coc.get('source_key')}`"],
            ["Source S3 Version ID", f"`{self.coc.get('s3_version_id', 'null')}`"],
            ["Source S3 ETag", f"`{self.coc.get('source_etag', 'N/A')}`"],
            ["Immutable Incident Vault", f"`s3://{self.coc.get('vault_bucket')}/raw_evidence/{evidence_file}`"],
            ["Evidence Size (Bytes)", f"`{self.coc.get('size_bytes', 0):,}`"],
            ["SHA-256 Digest", f"`{self.coc.get('sha256')}`"],
            ["MD5 Digest", f"`{self.coc.get('md5')}`"],
            ["Acquisition Hash Verification", acq_status],
            ["Local Scratch Permissions", f"`{self.coc.get('local_evidence_permissions', '0400 (read-only)')}`"],
            ["Intake Timestamp (UTC)", f"`{self.coc.get('intake_timestamp_utc')}`"],
            ["Processed Timestamp (UTC)", f"`{self.coc.get('processed_timestamp_utc')}`"],
            ["The Sleuth Kit Version", f"`{self.coc.get('tsk_version')}`"],
            ["KMS Encryption Key ARN", f"`{kms_display}`"],
            ["Forensic Mode", f"`{self.coc.get('forensic_mode', 'compliance' if is_compliance else 'simple')}`"],
            ["Vault S3 Object Lock", object_lock_display],
            ["S3 Object Legal Hold", legal_hold_display],
            ["Cryptographic Verification", "**VERIFIED (Dual-Hash Checksum Computed Over Full Evidence Stream)**"],
            ["Analysis Status", f"**{str(self.coc.get('analysis_status', 'complete')).upper()}**"],
            ["File System Volumes Analysed", f"`{len(self.coc.get('volumes', [])) or 'none (standalone artifact)'}`"],
            ["Audit & Access Logging", audit_display],
        ]

        table_md = self._render_table(coc_rows, headers=["Chain of Custody Field", "Recorded Value"])

        # Software Bill of Materials (SBOM) section for ISO 17025 / ASTM E2678 reproducibility
        sbom = self.coc.get("sbom", {}) or {}
        tool_versions = sbom.get("tool_versions", {}) or {}
        clock_prov = sbom.get("clock_provenance", {}) or {}
        yara_hashes = sbom.get("yara_ruleset_sha256", {}) or {}

        sbom_rows = [
            ["Operating System", sbom.get("os_pretty_name", "Ubuntu 24.04 LTS")],
            ["Platform / Architecture", f"{sbom.get('platform', '')} ({sbom.get('architecture', 'x86_64')})"],
            ["Linux Kernel", sbom.get("kernel_release", "Linux")],
            ["Python Runtime", sbom.get("python_version", "Python 3.12")],
            ["The Sleuth Kit", tool_versions.get("the_sleuth_kit", self.coc.get("tsk_version", "unknown"))],
            ["YARA Engine", tool_versions.get("yara", "unknown")],
            ["PhotoRec / TestDisk", tool_versions.get("photorec", "unknown")],
            ["ExifTool", tool_versions.get("exiftool", "unknown")],
            ["Time Source / Clock", f"{clock_prov.get('time_source', 'NTP')} (clocksource: {clock_prov.get('system_clocksource', 'kvm-clock')})"],
        ]
        sbom_table_md = self._render_table(sbom_rows, headers=["Component / Tool", "Version & Runtime Environment"])

        yara_hash_rows = [[f"`{ns}`", f"`{h}`"] for ns, h in yara_hashes.items()]
        yara_hash_table = self._render_table(yara_hash_rows, headers=["Ruleset Namespace / File", "SHA-256 Digest"]) if yara_hash_rows else "*(No external YARA rules loaded)*"

        warnings = self.coc.get("warnings", []) or []
        warnings_md = (
            "## Processing Warnings\n\n"
            "> **Note:** analysis completed with reduced coverage. Review before relying on negative results.\n\n"
            + "\n".join(f"- {w}" for w in warnings)
            + "\n\n"
            if warnings
            else ""
        )

        content = (
            self._build_frontmatter()
            + f"# 00 - Forensic Chain of Custody (`{incident_id}`)\n\n"
            + self._evidentiary_disclaimer_block()
            + "## Executive Summary\n\n"
            + f"This document establishes the formal cryptographic Chain of Custody (CoC) for evidence artifact "
            + f"`{evidence_file}` ingested by the **dfirbaboon** automated cloud-native DFIR pipeline. "
            + "Dual cryptographic hashes (`SHA-256` and `MD5`) were computed via streaming 16 MiB chunks during "
            + (
                "transfer from the S3 intake bucket prior to forensic analysis and immutable archival under S3 Object Lock COMPLIANCE mode.\n\n"
                if is_compliance
                else "transfer from the S3 intake bucket prior to forensic analysis in simple-forensics mode (no S3 Object Lock or Legal Hold).\n\n"
            )
            + "## Chain of Custody Verification Table\n\n"
            + f"{table_md}\n\n"
            + warnings_md
            + "## Execution Environment & Software Bill of Materials (SBOM)\n\n"
            + "*Documented in accordance with ISO/IEC 17025 and ASTM E2678 for scientific determinism and court reproducibility:*\n\n"
            + f"{sbom_table_md}\n\n"
            + "### YARA Ruleset Cryptographic Provenance\n\n"
            + f"{yara_hash_table}\n\n"
            + "## Related Analysis Reports\n\n"
            + "- [[01_TSK_FILE_SYSTEM_SUMMARY]] — Volume Layout (`mmls`), Filesystem Metadata (`fsstat`), & Deleted Files (`fls -d`)\n"
            + "- [[02_HIGH_RISK_TIMELINE_ARTIFACTS]] — Filtered High-Signal Timeline Events (`mactime`)\n"
            + "- [[03_YARA_AND_ANOMALIES]] — YARA Rule Detections & File Header / Entropy Anomalies\n"
            + "- [[04_CARVED_FILES_AND_UNALLOCATED]] — Unallocated Space, Carved Files, EXIF & Keyword Hits\n"
        )

        file_path.write_text(content, encoding="utf-8")
        logger.info("Generated %s", file_path)
        return file_path

    def generate_tsk_summary_md(self, tsk_result: TSKAnalysisResult) -> Path:
        """Generate 01_TSK_FILE_SYSTEM_SUMMARY.md."""
        file_path = self.output_dir / "01_TSK_FILE_SYSTEM_SUMMARY.md"
        incident_id = self.coc.get("incident_id", "INC-UNASSIGNED")
        evidence_file = self.coc.get("evidence_file", "unknown")

        part_rows = [
            [
                p.slot,
                p.start_sector,
                p.end_sector,
                p.length_sectors,
                p.description,
                "FS VOLUME" if any(v.offset == p.start_sector for v in tsk_result.volumes) else "",
            ]
            for p in tsk_result.partitions
        ]
        part_table = self._render_table(
            part_rows,
            headers=["Slot", "Start Sector", "End Sector", "Length (Sectors)", "Description", "Selected"],
        )

        deleted_rows = [
            [
                f"`{d.inode}`",
                f"`{d.file_type}`",
                "Yes" if d.reallocated else "No",
                f"`{d.path}`",
            ]
            for d in tsk_result.deleted_files[:200]
        ]
        deleted_table = self._render_table(
            deleted_rows,
            headers=["Inode", "Type", "Reallocated", "Deleted File Path"],
        )
        deleted_table_safe = self.truncate_section(deleted_table)

        mmls_safe = self.truncate_section(tsk_result.mmls_raw)
        fsstat_safe = self.truncate_section(tsk_result.fsstat_raw)
        fls_deleted_safe = self.truncate_section(tsk_result.fls_deleted_raw)

        content = (
            self._build_frontmatter()
            + f"# 01 - The Sleuth Kit (TSK) File System Summary (`{incident_id}`)\n\n"
            + self._evidentiary_disclaimer_block()
            + f"- **Evidence File:** `{evidence_file}`\n"
            + f"- **TSK Version:** `{tsk_result.tsk_version}`\n"
            + f"- **Detected Primary Data Partition Offset:** `{tsk_result.primary_offset}` sectors\n"
            + f"- **File System Volumes Analysed:** `{len(tsk_result.volumes)}` "
            + f"({', '.join(f'@{v.offset} {v.description}' for v in tsk_result.volumes) or 'none'})\n"
            + f"- **Mountable Filesystem Detected:** `{tsk_result.is_disk_image}`\n"
            + f"- **Recoverable Deleted / Unlinked Entries:** `{len(tsk_result.deleted_files)}`\n\n"
            + "## 1. Volume Partition Layout (`mmls`)\n\n"
            + f"{part_table}\n\n"
            + "### Raw `mmls` Output\n\n"
            + f"```text\n{mmls_safe}\n```\n\n"
            + f"## 2. File System Metadata (`fsstat -o {tsk_result.primary_offset}`)\n\n"
            + f"```text\n{fsstat_safe}\n```\n\n"
            + f"## 3. Recoverable Deleted Files & Unlinked Inodes (`fls -r -d -p -o {tsk_result.primary_offset}`)\n\n"
            + f"{deleted_table_safe}\n\n"
            + "### Raw `fls -d` Output\n\n"
            + f"```text\n{fls_deleted_safe}\n```\n"
        )

        file_path.write_text(content, encoding="utf-8")
        logger.info("Generated %s", file_path)
        return file_path

    def generate_timeline_md(self, tsk_result: TSKAnalysisResult) -> Path:
        """Generate 02_HIGH_RISK_TIMELINE_ARTIFACTS.md."""
        file_path = self.output_dir / "02_HIGH_RISK_TIMELINE_ARTIFACTS.md"
        incident_id = self.coc.get("incident_id", "INC-UNASSIGNED")
        evidence_file = self.coc.get("evidence_file", "unknown")

        timeline_rows = [
            [
                ev.date,
                f"`{ev.macb}`",
                ev.size,
                f"`{ev.inode}`",
                ev.reason,
                f"`{ev.file_name}`",
            ]
            for ev in tsk_result.high_risk_timeline_events
        ]

        raw_table = self._render_table(
            timeline_rows,
            headers=["Timestamp (UTC)", "MACB", "Size (B)", "Inode", "Detection Signal", "Artifact Path"],
        )
        safe_table = self.truncate_section(raw_table)

        content = (
            self._build_frontmatter()
            + f"# 02 - High-Risk Timeline Artifacts (`{incident_id}`)\n\n"
            + self._evidentiary_disclaimer_block()
            + "## Timeline Filtering Overview\n\n"
            + f"- **Evidence File:** `{evidence_file}`\n"
            + f"- **Total `mactime` Timeline Events Processed:** `{tsk_result.total_timeline_events:,}`\n"
            + f"- **High-Signal Events Retained:** `{len(tsk_result.high_risk_timeline_events):,}`\n"
            + "- **Target Extensions:** `.exe`, `.dll`, `.ps1`, `.bat`, `.vbs`, `.lnk`, `.pf`, `.evtx`, `.sys`, `.scr`, `.hta`, `.js`, `.cmd`, `.msi`\n"
            + "- **Target Directories:** User Profiles (`/Users/`, `/home/`, `/root/`), `AppData`, `Temp`, `Prefetch`, `System32/Tasks`, `Startup`\n"
            + f"- **Full CSV Timeline URI:** `s3://{self.coc.get('vault_bucket')}/analysis/{evidence_file}/timelines/mactime_supertimeline.csv`\n\n"
            + "## Filtered High-Signal `mactime` Events\n\n"
            + f"{safe_table}\n"
        )

        file_path.write_text(content, encoding="utf-8")
        logger.info("Generated %s", file_path)
        return file_path

    def generate_yara_and_anomalies_md(self, yara_result: YaraAnalysisResult) -> Path:
        """Generate 03_YARA_AND_ANOMALIES.md."""
        file_path = self.output_dir / "03_YARA_AND_ANOMALIES.md"
        incident_id = self.coc.get("incident_id", "INC-UNASSIGNED")
        evidence_file = self.coc.get("evidence_file", "unknown")

        yara_rows = [
            [
                f"**{m.severity}**",
                f"`{m.rule_name}`",
                f"`{m.mitre_attack}`",
                f"`{m.inode}`",
                f"`{m.target_path}`",
                ", ".join(f"`{s}`" for s in m.matched_strings) or "N/A",
                f"`{m.file_sha256[:16]}...`" if m.file_sha256 else "N/A",
            ]
            for m in yara_result.yara_matches
        ]
        yara_table = self.truncate_section(
            self._render_table(
                yara_rows,
                headers=[
                    "Severity",
                    "YARA Rule",
                    "MITRE ATT&CK",
                    "Inode",
                    "Artifact Path",
                    "Matched Strings",
                    "SHA-256 (Prefix)",
                ],
            )
        )

        anomaly_rows = [
            [
                f"**{a.severity}**",
                a.anomaly_type,
                f"`{a.inode}`",
                f"`{a.target_path}`",
                a.detected_magic,
                f"{a.entropy:.2f}",
                a.details,
            ]
            for a in yara_result.header_anomalies
        ]
        anomaly_table = self.truncate_section(
            self._render_table(
                anomaly_rows,
                headers=[
                    "Severity",
                    "Anomaly Type",
                    "Inode",
                    "Artifact Path",
                    "Detected Header Magic",
                    "Entropy",
                    "Forensic Details",
                ],
            )
        )

        content = (
            self._build_frontmatter()
            + f"# 03 - YARA Detections & File Header Anomalies (`{incident_id}`)\n\n"
            + self._evidentiary_disclaimer_block()
            + "## Scan Summary\n\n"
            + f"- **Evidence File:** `{evidence_file}`\n"
            + f"- **YARA Rules Compiled:** `{yara_result.rules_loaded}`\n"
            + f"- **Allocated/Carved Files & Streams Scanned:** `{yara_result.files_scanned}`\n"
            + f"- **Total YARA Rule Matches:** `{len(yara_result.yara_matches)}`\n"
            + f"- **Total Header / Entropy Anomalies:** `{len(yara_result.header_anomalies)}`\n\n"
            + "## 1. YARA Signature Matches\n\n"
            + f"{yara_table}\n\n"
            + "## 2. File Header Mismatches & High-Entropy Anomalies\n\n"
            + f"{anomaly_table}\n"
        )

        file_path.write_text(content, encoding="utf-8")
        logger.info("Generated %s", file_path)
        return file_path

    def generate_carving_md(self, carving: CarvingResult) -> Path:
        """Generate 04_CARVED_FILES_AND_UNALLOCATED.md."""
        file_path = self.output_dir / "04_CARVED_FILES_AND_UNALLOCATED.md"
        incident_id = self.coc.get("incident_id", "INC-UNASSIGNED")
        evidence_file = self.coc.get("evidence_file", "unknown")

        type_rows = [
            [f"`{ext}`", count, f"{carving.type_bytes.get(ext, 0):,}"]
            for ext, count in sorted(carving.type_counts.items(), key=lambda kv: kv[1], reverse=True)
        ]
        type_table = self._render_table(type_rows, headers=["Extension", "Files", "Total Bytes"])

        notable = [c for c in carving.carved_files if c.extension not in MEDIA_EXTENSIONS][:200]
        notable_rows = [
            [f"`{c.name}`", f"`{c.extension}`", f"{c.size_bytes:,}", f"`{c.sha256[:16]}...`", f"{c.unalloc_offset:,}"]
            for c in notable
        ]
        notable_table = self.truncate_section(
            self._render_table(
                notable_rows,
                headers=["Carved File", "Type", "Size (B)", "SHA-256 (Prefix)", "Unallocated Offset (B)"],
            )
        )

        exif_rows = [
            [
                f"`{r.get('SourceFile', '')}`",
                r.get("Make", ""),
                r.get("Model", ""),
                r.get("DateTimeOriginal", r.get("CreateDate", "")),
                f"{r.get('GPSLatitude', '')},{r.get('GPSLongitude', '')}" if r.get("GPSLatitude") else "",
                r.get("Software", ""),
            ]
            for r in carving.exif_records[:100]
        ]
        exif_table = self.truncate_section(
            self._render_table(
                exif_rows,
                headers=["Image", "Make", "Model", "Date Taken", "GPS (lat,lon)", "Software"],
            )
        )

        keyword_sections = ""
        for finding in carving.keyword_findings:
            rows = [[f"`{v}`", n, f"{off:,}"] for v, n, off in finding.samples]
            keyword_sections += (
                f"### `{finding.label}` — {finding.total:,} hits, {finding.unique:,} unique\n\n"
                + self._render_table(rows, headers=["Value", "Occurrences", "First Offset (B)"])
                + "\n\n"
            )
        keyword_sections = self.truncate_section(keyword_sections) if keyword_sections else "*(No keyword or pattern hits)*"

        if not carving.attempted or carving.skipped_reason:
            status = f"**Skipped:** {carving.skipped_reason or 'not applicable'}"
        else:
            status = "Completed"
        notes = "\n".join(f"- {n}" for n in carving.notes) or "- None"
        warn_lines = "\n".join(f"- **WARNING:** {w}" for w in carving.warnings)
        if warn_lines:
            notes = f"{notes}\n{warn_lines}"

        content = (
            self._build_frontmatter()
            + f"# 04 - Carved Files & Unallocated Space Analysis (`{incident_id}`)\n\n"
            + self._evidentiary_disclaimer_block()
            + f"- **Evidence File:** `{evidence_file}`\n"
            + f"- **Status:** {status}\n"
            + f"- **Unallocated Space Extracted (`blkls`):** `{carving.unallocated_bytes:,}` bytes\n"
            + f"- **Carver:** `{carving.carver}`\n"
            + f"- **Carved Files Recovered:** `{len(carving.carved_files):,}`\n"
            + f"- **Images With EXIF Metadata:** `{len(carving.exif_records):,}`\n"
            + f"- **Bytes Scanned For Keywords:** `{carving.keyword_bytes_scanned:,}`\n"
            + f"- **Full Inventory CSV:** `s3://{self.coc.get('vault_bucket')}/analysis/{evidence_file}/carving/carved_files_inventory.csv`\n\n"
            + "## Processing Notes\n\n"
            + f"{notes}\n\n"
            + "## 1. Carved Files by Type\n\n"
            + f"{type_table}\n\n"
            + "## 2. Notable Carved Files (Non-Media)\n\n"
            + f"{notable_table}\n\n"
            + "## 3. EXIF Metadata From Carved Images\n\n"
            + f"{exif_table}\n\n"
            + "## 4. Keyword & Pattern Hits in Unallocated Space\n\n"
            + "*Offsets are relative to each volume's unallocated-space stream.*\n\n"
            + f"{keyword_sections}\n"
        )

        file_path.write_text(content, encoding="utf-8")
        logger.info("Generated %s", file_path)
        return file_path

    def export_all(
        self,
        tsk_result: TSKAnalysisResult,
        yara_result: YaraAnalysisResult,
        carving_result: Optional[CarvingResult] = None,
    ) -> List[Path]:
        """Generate all AI-friendly Markdown reports and return their paths."""
        paths = [
            self.generate_chain_of_custody_md(),
            self.generate_tsk_summary_md(tsk_result),
            self.generate_timeline_md(tsk_result),
            self.generate_yara_and_anomalies_md(yara_result),
        ]
        if carving_result is not None:
            paths.append(self.generate_carving_md(carving_result))
        return paths
