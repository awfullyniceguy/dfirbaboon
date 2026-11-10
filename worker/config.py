"""Configuration management for the dfirbaboon forensic worker pipeline."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class WorkerConfig:
    """Strongly-typed, immutable runtime configuration for the forensic worker.

    Attributes:
        project_prefix: Prefix used for all provisioned AWS resources and buckets.
        log_level: Logging severity level (e.g., DEBUG, INFO, WARNING, ERROR).
        aws_region: AWS region for S3, KMS, and CloudWatch interactions.
        aws_account_id: 12-digit AWS account ID.
        kms_key_arn: Optional KMS Key ARN used for client-side or server-side vault encryption.
        output_directory: Scratch workspace directory for downloaded evidence and parsed outputs.
        dfir_tool_timeout_sec: Maximum execution time permitted for individual CLI forensic tools.
        retention_days: Compliance vault retention period in days (e.g., 365).
        enable_carving: Whether to run deep unallocated space carving via blkls + PhotoRec.
        enable_yara: Whether to compile and scan extracted files/streams with YARA.
        max_file_size_bytes: Maximum allowed evidence size in bytes (default: 500 GiB).
        s3_chunk_size_bytes: Streaming read chunk size for S3 multi-part transfer and hashing.
        parsers_enabled: Comma-separated list of enabled parser IDs (default: tsk,carving,yara).
        create_vault_bucket: Whether worker attempts to create/configure the incident vault bucket.
            Set to False in enterprise environments where buckets are pre-vended or managed by platform teams.
        vault_bucket_override: Explicit S3 bucket name for incident vault output. If provided, overrides template.
        vault_bucket_template: Template string for dynamic vault bucket naming.
            Supports {project_prefix}, {incident_id}, {account_id}, and {region}.
        vault_prefix: Optional S3 key prefix for storing evidence and analysis within a shared central bucket
            (e.g., 'incidents/{incident_id}/' or 'evidence/').
    """

    project_prefix: str = "dfirbaboon"
    log_level: str = "INFO"
    aws_region: str = "us-east-1"
    aws_account_id: str = ""
    kms_key_arn: Optional[str] = None
    output_directory: str = "/tmp/work"
    dfir_tool_timeout_sec: int = 3600
    retention_days: int = 365
    enable_carving: bool = True
    enable_yara: bool = True
    max_file_size_bytes: int = 500 * 1024 * 1024 * 1024  # 500 GiB
    s3_chunk_size_bytes: int = 16 * 1024 * 1024  # 16 MiB
    parsers_enabled: List[str] = field(default_factory=lambda: ["tsk", "carving", "yara"])
    create_vault_bucket: bool = True
    vault_bucket_override: Optional[str] = None
    vault_bucket_template: str = "{project_prefix}-{incident_id}-{account_id}"
    vault_prefix: str = ""
    yara_rules_dir: str = "/app/rules"

    def __post_init__(self) -> None:
        """Validate configuration parameters upon initialization."""
        if self.dfir_tool_timeout_sec <= 0:
            raise ValueError(f"dfir_tool_timeout_sec must be positive, got {self.dfir_tool_timeout_sec}")
        if self.retention_days <= 0:
            raise ValueError(f"retention_days must be positive, got {self.retention_days}")
        if self.s3_chunk_size_bytes < 1024 * 1024:
            raise ValueError(f"s3_chunk_size_bytes must be at least 1 MiB, got {self.s3_chunk_size_bytes}")
        if not self.output_directory:
            raise ValueError("output_directory cannot be empty")

    def resolve_vault_bucket_name(self, incident_id: str, account_id: str) -> str:
        """Resolve the target S3 vault bucket name based on explicit override or template."""
        if self.vault_bucket_override:
            return self.vault_bucket_override.strip()

        cleaned_inc = incident_id.lower().replace("_", "-")
        return self.vault_bucket_template.format(
            project_prefix=self.project_prefix.lower(),
            incident_id=cleaned_inc,
            account_id=account_id.strip(),
            region=self.aws_region.lower(),
        )

    def resolve_vault_key(self, relative_key: str, incident_id: str) -> str:
        """Resolve the full S3 object key applying optional enterprise vault_prefix."""
        rel = relative_key.lstrip("/")
        if not self.vault_prefix:
            return rel

        prefix = self.vault_prefix.format(
            project_prefix=self.project_prefix.lower(),
            incident_id=incident_id.upper(),
            region=self.aws_region.lower(),
        ).strip("/")
        return f"{prefix}/{rel}"

    @classmethod
    def from_env(cls) -> "WorkerConfig":
        """Construct WorkerConfig from process environment variables with safe defaults."""
        project_prefix = os.getenv("PROJECT_PREFIX", "dfirbaboon").strip()
        log_level = os.getenv("LOG_LEVEL", "INFO").strip().upper()
        aws_region = os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", "us-east-1")).strip()
        aws_account_id = os.getenv("AWS_ACCOUNT_ID", "").strip()
        kms_key_arn = os.getenv("KMS_KEY_ARN", "").strip() or None
        output_directory = os.getenv("BATCH_SCRATCH_DIR", os.getenv("OUTPUT_DIR", "/tmp/work")).strip()

        try:
            dfir_tool_timeout_sec = int(os.getenv("DFIR_TOOL_TIMEOUT_SEC", "3600"))
        except ValueError:
            dfir_tool_timeout_sec = 3600

        try:
            retention_days = int(os.getenv("RETENTION_DAYS", "365"))
        except ValueError:
            retention_days = 365

        try:
            max_file_size_bytes = int(os.getenv("MAX_FILE_SIZE_BYTES", str(500 * 1024 * 1024 * 1024)))
        except ValueError:
            max_file_size_bytes = 500 * 1024 * 1024 * 1024

        try:
            s3_chunk_size_bytes = int(os.getenv("S3_CHUNK_SIZE_BYTES", str(16 * 1024 * 1024)))
        except ValueError:
            s3_chunk_size_bytes = 16 * 1024 * 1024

        enable_carving = os.getenv("ENABLE_CARVING", "true").strip().lower() in ("1", "true", "yes")
        enable_yara = os.getenv("ENABLE_YARA", "true").strip().lower() in ("1", "true", "yes")

        raw_parsers = os.getenv("PARSERS_ENABLED", "tsk,carving,yara").strip()
        parsers_enabled = [p.strip().lower() for p in raw_parsers.split(",") if p.strip()]

        create_vault_bucket = os.getenv("CREATE_VAULT_BUCKET", "true").strip().lower() in ("1", "true", "yes")
        vault_bucket_override = os.getenv("VAULT_BUCKET", "").strip() or None
        vault_bucket_template = os.getenv("VAULT_BUCKET_TEMPLATE", "{project_prefix}-{incident_id}-{account_id}").strip()
        vault_prefix = os.getenv("VAULT_PREFIX", "").strip()
        yara_rules_dir = os.getenv("YARA_RULES_DIR", "/app/rules").strip()

        return cls(
            project_prefix=project_prefix,
            log_level=log_level,
            aws_region=aws_region,
            aws_account_id=aws_account_id,
            kms_key_arn=kms_key_arn,
            output_directory=output_directory,
            dfir_tool_timeout_sec=dfir_tool_timeout_sec,
            retention_days=retention_days,
            enable_carving=enable_carving,
            enable_yara=enable_yara,
            max_file_size_bytes=max_file_size_bytes,
            s3_chunk_size_bytes=s3_chunk_size_bytes,
            parsers_enabled=parsers_enabled,
            create_vault_bucket=create_vault_bucket,
            vault_bucket_override=vault_bucket_override,
            vault_bucket_template=vault_bucket_template,
            vault_prefix=vault_prefix,
            yara_rules_dir=yara_rules_dir,
        )
