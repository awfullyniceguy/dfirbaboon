#!/usr/bin/env python3
"""Main orchestrator for the dfirbaboon headless serverless DFIR worker.

Runs on ECS Fargate (small images) or AWS Batch on EC2 (large images). Large evidence is downloaded with parallel
ranged reads, hashed in a second pass, preserved in the vault before analysis starts, and analysed with TSK and
carving running concurrently. Progress is checkpointed to the vault: a chain_of_custody.json (status=processing)
is uploaded right after hashing and replaced with the final (or failed) manifest.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

try:
    from config import WorkerConfig
    from parsers.base import ParserContext, ParserFactory, ParserResult
    from parsers.carving import CarvingEngine, run_carving
    from parsers.md_exporter import MarkdownExporter
    from parsers.tsk_parser import TSKParser
    from parsers.yara_scanner import YaraScanner
except ImportError:
    from worker.config import WorkerConfig
    from worker.parsers.base import ParserContext, ParserFactory, ParserResult
    from worker.parsers.carving import CarvingEngine, run_carving
    from worker.parsers.md_exporter import MarkdownExporter
    from worker.parsers.tsk_parser import TSKParser
    from worker.parsers.yara_scanner import YaraScanner

STREAM_CHUNK_SIZE = 16 * 1024 * 1024  # 16 MiB streaming/hash chunks
STREAMING_DOWNLOAD_MAX_BYTES = 5 * 1024 ** 3  # <= 5 GiB: single-stream download hashed on the fly
INCIDENT_REGEX = re.compile(r"(INC\d+)", re.IGNORECASE)


def configure_logging() -> logging.Logger:
    """Configure logging to stdout for CloudWatch Logs."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        stream=sys.stdout,
    )
    logging.Formatter.converter = lambda *args: datetime.datetime.now(datetime.timezone.utc).timetuple()
    return logging.getLogger("dfirbaboon.entrypoint")


logger = configure_logging()


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_incident_id(source_key: str) -> str:
    """Parse SOURCE_KEY using regex r'(INC\\d+)' (case-insensitive) or default to INC-UNASSIGNED."""
    match = INCIDENT_REGEX.search(source_key)
    return match.group(1).upper() if match else "INC-UNASSIGNED"


def resolve_aws_account_id(sts_client: Any) -> str:
    """Retrieve AWS_ACCOUNT_ID from environment or STS GetCallerIdentity."""
    env_account = os.environ.get("AWS_ACCOUNT_ID", "").strip()
    if env_account:
        return env_account
    return str(sts_client.get_caller_identity()["Account"])


def provision_incident_vault_bucket(
    s3_client: Any,
    bucket_name: str,
    region: str,
    kms_key_arn: str,
    create_bucket: bool = True,
    compliance_mode: bool = False,
    retention_days: int = 365,
) -> None:
    """Ensure the S3 incident vault bucket exists and is configured for the active forensic mode.

    In compliance mode, enables Object Lock (COMPLIANCE retention), versioning, SSE-KMS, and Glacier IR lifecycle.
    In simple mode, creates a standard encrypted bucket without Object Lock or versioning for rapid teardown.
    If create_bucket is False, assumes the bucket has been pre-provisioned and verifies existence via head_bucket.
    """
    if not create_bucket:
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            logger.info("Verified pre-provisioned incident vault bucket exists: s3://%s", bucket_name)
        except ClientError as exc:
            error_code = str(exc.response.get("Error", {}).get("Code", ""))
            if error_code in ("403", "AccessDenied"):
                logger.warning(
                    "Received 403 on head_bucket for pre-provisioned %s; assuming bucket exists with restricted permissions.",
                    bucket_name,
                )
            else:
                logger.error("Pre-provisioned vault bucket s3://%s is not accessible: %s", bucket_name, exc)
                raise
        return

    bucket_exists = False
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        bucket_exists = True
        logger.info("Incident vault bucket already exists: s3://%s", bucket_name)
    except ClientError as exc:
        error_code = str(exc.response.get("Error", {}).get("Code", ""))
        if error_code in ("404", "NoSuchBucket"):
            bucket_exists = False
        elif error_code in ("403", "AccessDenied"):
            logger.warning("Received 403 on head_bucket for %s; assuming bucket exists.", bucket_name)
            bucket_exists = True
        else:
            raise

    if not bucket_exists:
        logger.info(
            "Creating incident vault bucket s3://%s in region %s (mode=%s).",
            bucket_name, region, "compliance" if compliance_mode else "simple",
        )
        create_kwargs: Dict[str, Any] = {"Bucket": bucket_name}
        if compliance_mode:
            create_kwargs["ObjectLockEnabledForBucket"] = True
        if region and region != "us-east-1":
            create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
        try:
            s3_client.create_bucket(**create_kwargs)
        except ClientError as exc:
            err_code = str(exc.response.get("Error", {}).get("Code", ""))
            if err_code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                raise
            logger.info("Bucket s3://%s was concurrently created by another worker task.", bucket_name)

    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )

    encryption_rule: Dict[str, Any] = {
        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms" if kms_key_arn else "AES256"},
        "BucketKeyEnabled": bool(kms_key_arn),
    }
    if kms_key_arn:
        encryption_rule["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"] = kms_key_arn
    s3_client.put_bucket_encryption(
        Bucket=bucket_name, ServerSideEncryptionConfiguration={"Rules": [encryption_rule]}
    )

    if not compliance_mode:
        logger.info("Simple-forensics mode active: skipping Object Lock, versioning, and Glacier IR lifecycle on %s.", bucket_name)
        return

    s3_client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"})

    try:
        s3_client.put_object_lock_configuration(
            Bucket=bucket_name,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": retention_days}},
            },
        )
    except ClientError as exc:
        logger.warning("Could not set default Object Lock retention rule on %s: %s", bucket_name, exc)

    # Configure lifecycle transition to Glacier Instant Retrieval (GLACIER_IR)
    # Drops raw evidence storage cost from $0.023/GB-mo down to ~$0.004/GB-mo (~83% savings)
    try:
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "transition-raw-evidence-to-glacier-ir",
                        "Status": "Enabled",
                        "Filter": {"Prefix": "raw_evidence/"},
                        "Transitions": [
                            {"Days": 1, "StorageClass": "GLACIER_IR"}
                        ],
                    }
                ]
            },
        )
    except ClientError as exc:
        logger.warning("Could not set lifecycle rule on %s: %s", bucket_name, exc)


def retrieve_acquisition_hashes(
    s3_client: Any, source_bucket: str, source_key: str, s3_metadata: Dict[str, str]
) -> Tuple[Optional[str], Optional[str], str]:
    """Inspect S3 object metadata and optional adjacent manifest.json for collector acquisition hashes.

    Returns (expected_sha256, expected_md5, source_description).
    """
    lower_meta = {k.lower(): v for k, v in (s3_metadata or {}).items()}
    expected_sha256 = (
        lower_meta.get("acquisition-sha256")
        or lower_meta.get("acquisition_sha256")
        or lower_meta.get("expected-sha256")
        or lower_meta.get("expected_sha256")
        or lower_meta.get("sha256")
    )
    expected_md5 = (
        lower_meta.get("acquisition-md5")
        or lower_meta.get("acquisition_md5")
        or lower_meta.get("expected-md5")
        or lower_meta.get("expected_md5")
        or lower_meta.get("md5")
    )
    if expected_sha256:
        return expected_sha256.strip().lower(), expected_md5.strip().lower() if expected_md5 else None, "s3_object_metadata"

    possible_keys = [
        f"{source_key}.manifest.json",
        f"{source_key}.json",
        f"{Path(source_key).parent}/manifest.json" if "/" in source_key else "manifest.json",
    ]
    for m_key in possible_keys:
        try:
            resp = s3_client.get_object(Bucket=source_bucket, Key=m_key)
            manifest_data = json.loads(resp["Body"].read().decode("utf-8", errors="replace"))
            m_lower = {k.lower(): v for k, v in manifest_data.items() if isinstance(v, str)}
            found_sha = (
                m_lower.get("acquisition-sha256")
                or m_lower.get("acquisition_sha256")
                or m_lower.get("sha256")
                or m_lower.get("expected_sha256")
            )
            found_md5 = (
                m_lower.get("acquisition-md5")
                or m_lower.get("acquisition_md5")
                or m_lower.get("md5")
            )
            if found_sha:
                logger.info("Found collector acquisition hash in manifest s3://%s/%s", source_bucket, m_key)
                return found_sha.strip().lower(), found_md5.strip().lower() if found_md5 else None, f"manifest:{m_key}"
        except ClientError:
            continue
        except Exception as exc:
            logger.debug("Manifest check skipped for %s: %s", m_key, exc)

    return None, None, "none"


def capture_execution_sbom(tsk_version: str, yara_scanner: Optional[Any] = None) -> Dict[str, Any]:
    """Capture full runtime environment, binary versions, YARA ruleset hashes, and clock provenance for ISO 17025 / ASTM E2678 reproducibility."""
    import platform
    import subprocess

    def _cmd_version(cmd: List[str]) -> str:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            return (p.stdout or p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr) else "unknown"
        except Exception:
            return "not-installed"

    os_name = "Ubuntu 24.04 LTS"
    os_rel_path = Path("/etc/os-release")
    if os_rel_path.exists():
        for line in os_rel_path.read_text(errors="replace").splitlines():
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[1].strip('"')
                break

    clocksource = "unknown"
    cs_path = Path("/sys/devices/system/clocksource/clocksource0/current_clocksource")
    if cs_path.exists():
        clocksource = cs_path.read_text(errors="replace").strip()

    return {
        "os_pretty_name": os_name,
        "platform": platform.platform(),
        "kernel_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": sys.version.splitlines()[0],
        "tool_versions": {
            "the_sleuth_kit": tsk_version,
            "yara": _cmd_version(["yara", "--version"]),
            "photorec": _cmd_version(["photorec", "/version"]),
            "exiftool": _cmd_version(["exiftool", "-ver"]),
        },
        "container_environment": {
            "image_tag": os.environ.get("IMAGE_TAG", "latest"),
            "image_digest": os.environ.get("IMAGE_DIGEST", "unavailable-in-container"),
            "execution_id": os.environ.get("ECS_CONTAINER_METADATA_URI_V4", "").split("/")[-1] or os.environ.get("AWS_BATCH_JOB_ID", "local"),
        },
        "yara_ruleset_sha256": getattr(yara_scanner, "ruleset_hashes", {}) if yara_scanner else {},
        "clock_provenance": {
            "system_utc_time": utc_now(),
            "time_source": "AWS_NTP_Chronos" if Path("/etc/chrony.conf").exists() else "Linux_System_Clock",
            "system_clocksource": clocksource,
        },
    }


def hash_file(path: Path) -> Dict[str, str]:
    """Compute SHA-256 and MD5 over a file in 16 MiB chunks."""
    sha256_hasher = hashlib.sha256()
    md5_hasher = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(STREAM_CHUNK_SIZE), b""):
            sha256_hasher.update(chunk)
            md5_hasher.update(chunk)
    return {"sha256": sha256_hasher.hexdigest(), "md5": md5_hasher.hexdigest()}


def download_and_hash(s3_client: Any, source_bucket: str, source_key: str, local_dest: Path) -> Dict[str, Any]:
    """Download evidence and compute dual SHA-256 / MD5 digests.

    Images up to 5 GiB are streamed once in 16 MiB chunks (hashes computed on the fly). Larger images use parallel
    ranged reads (resumable per part, many times faster than one stream) followed by a sequential hashing pass.
    Fails fast if the scratch disk cannot hold the image.
    """
    local_dest.parent.mkdir(parents=True, exist_ok=True)
    head_resp = s3_client.head_object(Bucket=source_bucket, Key=source_key)
    s3_version_id = str(head_resp.get("VersionId", "null"))
    expected_size = int(head_resp["ContentLength"])
    last_modified = head_resp.get("LastModified")
    intake_utc = (
        last_modified.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if isinstance(last_modified, datetime.datetime)
        else utc_now()
    )

    free = shutil.disk_usage(local_dest.parent).free
    if expected_size * 1.05 > free:
        raise RuntimeError(
            f"Insufficient scratch space: evidence is {expected_size:,} bytes but only {free:,} bytes are free. "
            "Route this evidence to the AWS Batch (large image) path or increase scratch storage."
        )

    version_args: Dict[str, Any] = {}
    if s3_version_id and s3_version_id != "null":
        version_args["VersionId"] = s3_version_id

    logger.info(
        "Downloading s3://%s/%s (%d bytes, %s)",
        source_bucket, source_key, expected_size,
        "streaming" if expected_size <= STREAMING_DOWNLOAD_MAX_BYTES else "parallel ranged",
    )

    if expected_size <= STREAMING_DOWNLOAD_MAX_BYTES:
        body = s3_client.get_object(Bucket=source_bucket, Key=source_key, **version_args)["Body"]
        sha256_hasher = hashlib.sha256()
        md5_hasher = hashlib.md5()
        total_bytes = 0
        with local_dest.open("wb") as file_out:
            for chunk in iter(lambda: body.read(STREAM_CHUNK_SIZE), b""):
                file_out.write(chunk)
                sha256_hasher.update(chunk)
                md5_hasher.update(chunk)
                total_bytes += len(chunk)
        digests = {"sha256": sha256_hasher.hexdigest(), "md5": md5_hasher.hexdigest()}
    else:
        concurrency = int(os.environ.get("DOWNLOAD_CONCURRENCY", "16"))
        s3_client.download_file(
            source_bucket,
            source_key,
            str(local_dest),
            ExtraArgs=version_args or None,
            Config=TransferConfig(
                multipart_threshold=64 * 1024 * 1024,
                multipart_chunksize=64 * 1024 * 1024,
                max_concurrency=concurrency,
                use_threads=True,
            ),
        )
        total_bytes = local_dest.stat().st_size
        logger.info("Download complete (%d bytes); hashing evidence.", total_bytes)
        digests = hash_file(local_dest)

    if total_bytes != expected_size:
        raise RuntimeError(f"Downloaded size {total_bytes} does not match S3 object size {expected_size}.")

    # Enforce read-only permissions (chmod 0400) immediately after download & hash (ASTM E3016 / ISO 27037)
    try:
        os.chmod(local_dest, 0o400)
        logger.info("Enforced strict read-only permissions (chmod 0400) on %s", local_dest)
    except OSError as exc:
        logger.warning("Could not set chmod 0400 on %s: %s", local_dest, exc)

    # Verification against collector acquisition hash if provided (NIST SP 800-86 / FRE 1006)
    expected_sha256, expected_md5, acq_source = retrieve_acquisition_hashes(
        s3_client, source_bucket, source_key, head_resp.get("Metadata", {})
    )
    acq_verified = False
    if expected_sha256:
        if digests["sha256"].lower() != expected_sha256.lower():
            raise ValueError(
                f"CRITICAL EVIDENCE INTEGRITY FAILURE (FRE/NIST SP 800-86): Ingest SHA-256 {digests['sha256']} "
                f"does NOT match collector acquisition hash {expected_sha256} from {acq_source}!"
            )
        acq_verified = True
        logger.info(
            "Collector acquisition hash verified successfully against %s (SHA-256=%s)",
            acq_source, expected_sha256,
        )

    logger.info(
        "Evidence ready: %s (%d bytes) | SHA-256=%s | MD5=%s | AcqVerified=%s",
        local_dest.name, total_bytes, digests["sha256"], digests["md5"], acq_verified,
    )
    return {
        "s3_version_id": s3_version_id,
        "size_bytes": total_bytes,
        "sha256": digests["sha256"],
        "md5": digests["md5"],
        "acquisition_hash_verified": acq_verified,
        "acquisition_sha256": expected_sha256,
        "acquisition_source": acq_source,
        "local_evidence_permissions": "0400 (read-only)",
        "intake_timestamp_utc": intake_utc,
        "etag": str(head_resp.get("ETag", "")).strip('"'),
    }


def _sse_args(kms_key_arn: str) -> Dict[str, Any]:
    if kms_key_arn:
        return {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": kms_key_arn}
    return {}


def copy_evidence_to_vault(
    s3_client: Any,
    source_bucket: str,
    source_key: str,
    dest_bucket: str,
    evidence_filename: str,
    kms_key_arn: str,
    coc_metadata: Dict[str, Any],
    dest_key: Optional[str] = None,
    compliance_mode: bool = False,
) -> None:
    """Copy the original evidence object (server-side, multipart) to s3://<dest>/<dest_key>."""
    raw_dest_key = dest_key or f"raw_evidence/{evidence_filename}"
    logger.info("Copying evidence to s3://%s/%s", dest_bucket, raw_dest_key)
    copy_source: Dict[str, str] = {"Bucket": source_bucket, "Key": source_key}
    if coc_metadata.get("s3_version_id") and coc_metadata["s3_version_id"] != "null":
        copy_source["VersionId"] = str(coc_metadata["s3_version_id"])

    extra = _sse_args(kms_key_arn)
    if compliance_mode:
        extra["StorageClass"] = "GLACIER_IR"
    extra["Metadata"] = {
        "incident-id": str(coc_metadata.get("incident_id", "")),
        "sha256": str(coc_metadata.get("sha256", "")),
        "md5": str(coc_metadata.get("md5", "")),
        "pipeline": "dfirbaboon",
    }
    extra["MetadataDirective"] = "REPLACE"
    s3_client.copy(
        CopySource=copy_source,
        Bucket=dest_bucket,
        Key=raw_dest_key,
        ExtraArgs=extra,
        Config=TransferConfig(
            multipart_threshold=256 * 1024 * 1024,
            multipart_chunksize=256 * 1024 * 1024,
            max_concurrency=int(os.environ.get("COPY_CONCURRENCY", "16")),
        ),
    )

    if compliance_mode:
        # Apply S3 Legal Hold to raw evidence (NIST SP 800-86 / OSAC Evidence Preservation)
        try:
            s3_client.put_object_legal_hold(
                Bucket=dest_bucket,
                Key=raw_dest_key,
                LegalHold={"Status": "ON"},
            )
            logger.info("Applied S3 Legal Hold (Status=ON) to s3://%s/%s", dest_bucket, raw_dest_key)
        except ClientError as exc:
            logger.warning("Could not apply S3 Legal Hold to s3://%s/%s: %s", dest_bucket, raw_dest_key, exc)


def upload_file(
    s3_client: Any, path: Path, bucket: str, key: str, kms_key_arn: str, content_type: str
) -> None:
    """Upload one file to the vault with SSE-KMS."""
    extra = _sse_args(kms_key_arn)
    extra["ContentType"] = content_type
    logger.info("Uploading s3://%s/%s", bucket, key)
    s3_client.upload_file(str(path), bucket, key, ExtraArgs=extra)


def write_and_upload_coc(
    s3_client: Any,
    coc: Dict[str, Any],
    work_dir: Path,
    dest_bucket: str,
    filename: str,
    kms_key_arn: str,
    dest_key: Optional[str] = None,
) -> Path:
    """Write chain_of_custody.json locally and checkpoint it into the vault."""
    path = work_dir / "chain_of_custody.json"
    path.write_text(json.dumps(coc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    target_key = dest_key or f"analysis/{filename}/chain_of_custody.json"
    upload_file(s3_client, path, dest_bucket, target_key, kms_key_arn, "application/json")
    return path


def run_analysis(
    local_evidence_path: Path,
    work_dir: Path,
    stream_meta: Dict[str, Any],
    checkpoint_callback: Optional[Callable[[str, Path], None]] = None,
    custom_rules_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """TSK file system analysis and unallocated-space carving run concurrently, then YARA scans everything.

    Checkpoints are emitted immediately as each phase completes so large datasets are safely vaulted before subsequent phases.
    """
    tsk_parser = TSKParser(image_path=str(local_evidence_path), work_dir=str(work_dir / "tsk"))
    timeline_csv_path = work_dir / "timelines" / "mactime_supertimeline.csv"

    layout = tsk_parser.detect_layout()
    logger.info(
        "Layout: %d file system volume(s): %s",
        len(layout.volumes), [(v.offset, v.description) for v in layout.volumes],
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        tsk_future = pool.submit(tsk_parser.analyze_filesystem, layout, str(timeline_csv_path))
        carve_future = pool.submit(
            run_carving, str(local_evidence_path), str(work_dir / "carving"), [v.offset for v in layout.volumes]
        )
        tsk_result = tsk_future.result()
        if checkpoint_callback and timeline_csv_path.exists():
            checkpoint_callback("timeline", timeline_csv_path)

        carving_result = carve_future.result()
        if checkpoint_callback and carving_result.inventory_csv_path and Path(carving_result.inventory_csv_path).exists():
            checkpoint_callback("carving", Path(carving_result.inventory_csv_path))

    yara_scanner = YaraScanner(custom_rules_dir=custom_rules_dir)
    scan_records = list(tsk_result.extracted_files) + CarvingEngine.to_scan_records(carving_result.carved_files)
    yara_result = yara_scanner.scan_artifacts(
        raw_evidence_path=str(local_evidence_path),
        extracted_files=scan_records,
        raw_evidence_sha256=stream_meta["sha256"],
        unallocated_paths=carving_result.unallocated_paths,
    )
    return {
        "tsk": tsk_result,
        "carving": carving_result,
        "yara": yara_result,
        "yara_scanner": yara_scanner,
        "timeline_csv": timeline_csv_path,
        "layout": layout,
    }


def main() -> int:
    """Execute the end-to-end dfirbaboon forensic processing pipeline."""
    config = WorkerConfig.from_env()

    source_bucket = os.environ.get("SOURCE_BUCKET", "").strip()
    raw_source_key = os.environ.get("SOURCE_KEY", "").strip()
    source_etag = os.environ.get("SOURCE_ETAG", "").strip().strip('"')
    project_prefix = config.project_prefix
    kms_key_arn = config.kms_key_arn or os.environ.get("KMS_KEY_ARN", "").strip()
    aws_region = config.aws_region
    work_dir = Path(config.output_directory).resolve()

    dest_bucket = ""
    coc_metadata: Dict[str, Any] = {}
    evidence_filename = ""
    coc_key = ""
    s3_client: Any = None

    def handle_shutdown_signal(signum: int, _frame: Any) -> None:
        sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
        logger.warning("Received shutdown signal %s. Initiating graceful shutdown and vault checkpoint...", sig_name)
        if dest_bucket and coc_metadata and s3_client and evidence_filename:
            try:
                coc_metadata.update({
                    "status": f"interrupted_{sig_name.lower()}",
                    "error": f"Pipeline terminated prematurely by {sig_name}",
                    "processed_timestamp_utc": utc_now(),
                })
                target_key = coc_key or f"analysis/{evidence_filename}/chain_of_custody.json"
                write_and_upload_coc(s3_client, coc_metadata, work_dir, dest_bucket, evidence_filename, kms_key_arn, dest_key=target_key)
                logger.info("Successfully uploaded interruption checkpoint to s3://%s/%s", dest_bucket, target_key)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to upload interruption checkpoint: %s", exc)
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, handle_shutdown_signal)
    signal.signal(signal.SIGINT, handle_shutdown_signal)

    if not source_bucket or not raw_source_key:
        logger.error("Missing required environment variables SOURCE_BUCKET (%r) or SOURCE_KEY (%r).", source_bucket, raw_source_key)
        return 1

    source_key = urllib.parse.unquote_plus(raw_source_key)
    if source_key.endswith("/"):
        logger.info("Ignoring folder placeholder object key: %s", source_key)
        return 0

    evidence_filename = Path(source_key).name
    incident_id = extract_incident_id(source_key)
    logger.info(
        "Starting dfirbaboon pipeline | Mode=%s | Incident=%s | Source=s3://%s/%s",
        config.forensic_mode, incident_id, source_bucket, source_key,
    )

    session = boto3.session.Session(region_name=aws_region)
    boto_config = Config(retries={"max_attempts": 10, "mode": "adaptive"}, read_timeout=300, connect_timeout=30, max_pool_connections=64)
    s3_client = session.client("s3", config=boto_config)
    sts_client = session.client("sts")

    try:
        aws_account_id = config.aws_account_id or resolve_aws_account_id(sts_client)
        dest_bucket = config.resolve_vault_bucket_name(incident_id, aws_account_id)
        raw_evidence_key = config.resolve_vault_key(f"raw_evidence/{evidence_filename}", incident_id)
        coc_key = config.resolve_vault_key(f"analysis/{evidence_filename}/chain_of_custody.json", incident_id)
        base_s3_prefix = config.resolve_vault_key(f"analysis/{evidence_filename}", incident_id)

        # Step 1: verify or provision & configure the dynamic incident vault
        provision_incident_vault_bucket(
            s3_client,
            dest_bucket,
            aws_region,
            kms_key_arn,
            create_bucket=config.create_vault_bucket,
            compliance_mode=config.is_compliance_mode,
            retention_days=config.retention_days,
        )

        # Step 2: download and hash the evidence
        work_dir.mkdir(parents=True, exist_ok=True)
        local_evidence_path = work_dir / evidence_filename
        stream_meta = download_and_hash(s3_client, source_bucket, source_key, local_evidence_path)

        coc_metadata = {
            "tool": "dfirbaboon",
            "forensic_mode": config.forensic_mode,
            "object_lock_enabled": config.is_compliance_mode,
            "legal_hold_applied": config.is_compliance_mode,
            "status": "processing",
            "incident_id": incident_id,
            "evidence_file": evidence_filename,
            "source_bucket": source_bucket,
            "source_key": source_key,
            "source_etag": source_etag or stream_meta.get("etag", ""),
            "s3_version_id": stream_meta["s3_version_id"],
            "vault_bucket": dest_bucket,
            "vault_prefix": config.vault_prefix,
            "raw_evidence_key": raw_evidence_key,
            "size_bytes": stream_meta["size_bytes"],
            "sha256": stream_meta["sha256"],
            "md5": stream_meta["md5"],
            "acquisition_hash_verified": stream_meta.get("acquisition_hash_verified", False),
            "acquisition_sha256": stream_meta.get("acquisition_sha256"),
            "acquisition_source": stream_meta.get("acquisition_source", "none"),
            "local_evidence_permissions": stream_meta.get("local_evidence_permissions", "0400 (read-only)"),
            "intake_timestamp_utc": stream_meta["intake_timestamp_utc"],
            "processed_timestamp_utc": None,
            "kms_key_arn": kms_key_arn,
            "compute": os.environ.get("AWS_BATCH_JOB_ID") and "aws-batch-ec2" or "ecs-fargate",
        }

        # Step 3: preserve evidence + checkpoint the chain of custody BEFORE analysis starts
        copy_evidence_to_vault(
            s3_client,
            source_bucket,
            source_key,
            dest_bucket,
            evidence_filename,
            kms_key_arn,
            coc_metadata,
            dest_key=raw_evidence_key,
            compliance_mode=config.is_compliance_mode,
        )
        write_and_upload_coc(s3_client, coc_metadata, work_dir, dest_bucket, evidence_filename, kms_key_arn, dest_key=coc_key)

        # Step 4: analysis (TSK || carving) then YARA with incremental S3 checkpointing
        def checkpoint(artifact_type: str, file_path: Path) -> None:
            if artifact_type == "timeline":
                upload_file(
                    s3_client, file_path, dest_bucket,
                    f"{base_s3_prefix}/timelines/mactime_supertimeline.csv", kms_key_arn, "text/csv"
                )
            elif artifact_type == "carving":
                upload_file(
                    s3_client, file_path, dest_bucket,
                    f"{base_s3_prefix}/carving/carved_files_inventory.csv", kms_key_arn, "text/csv"
                )

        analysis = run_analysis(
            local_evidence_path,
            work_dir,
            stream_meta,
            checkpoint_callback=checkpoint,
            custom_rules_dir=config.yara_rules_dir,
        )
        tsk_result, carving_result, yara_result = analysis["tsk"], analysis["carving"], analysis["yara"]
        timeline_csv_path: Path = analysis["timeline_csv"]

        # Capture Software Bill of Materials (SBOM) for court reproducibility (ISO 17025 / ASTM E2678)
        sbom = capture_execution_sbom(tsk_result.tsk_version, yara_scanner=analysis.get("yara_scanner"))

        warnings: List[str] = list(tsk_result.warnings) + list(carving_result.warnings) + list(yara_result.warnings)
        coc_metadata.update(
            {
                "status": "complete" if not warnings else "complete_with_warnings",
                "analysis_status": "complete" if not warnings else "complete_with_warnings",
                "warnings": warnings,
                "sbom": sbom,
                "processed_timestamp_utc": utc_now(),
                "tsk_version": tsk_result.tsk_version,
                "volumes": [
                    {"index": v.index, "offset_sectors": v.offset, "description": v.description}
                    for v in tsk_result.volumes
                ],
                "primary_partition_offset": tsk_result.primary_offset,
                "is_disk_image": tsk_result.is_disk_image,
                "recoverable_deleted_files_count": len(tsk_result.deleted_files),
                "total_timeline_events": tsk_result.total_timeline_events,
                "high_risk_timeline_events_count": len(tsk_result.high_risk_timeline_events),
                "yara_matches_count": len(yara_result.yara_matches),
                "header_anomalies_count": len(yara_result.header_anomalies),
                "unallocated_bytes": carving_result.unallocated_bytes,
                "carver": carving_result.carver,
                "carved_files_count": len(carving_result.carved_files),
                "carved_file_types": carving_result.type_counts,
                "exif_records_count": len(carving_result.exif_records),
                "keyword_patterns_hit": [f.label for f in carving_result.keyword_findings],
            }
        )

        # Step 5: reports
        md_exporter = MarkdownExporter(output_dir=str(work_dir / "markdown"), coc_metadata=coc_metadata)
        markdown_files = md_exporter.export_all(tsk_result=tsk_result, yara_result=yara_result, carving_result=carving_result)

        # Step 6: upload outputs
        coc_json_path = write_and_upload_coc(s3_client, coc_metadata, work_dir, dest_bucket, evidence_filename, kms_key_arn, dest_key=coc_key)
        upload_file(s3_client, timeline_csv_path, dest_bucket, f"{base_s3_prefix}/timelines/mactime_supertimeline.csv", kms_key_arn, "text/csv")
        if carving_result.inventory_csv_path and Path(carving_result.inventory_csv_path).is_file():
            upload_file(
                s3_client, Path(carving_result.inventory_csv_path), dest_bucket,
                f"{base_s3_prefix}/carving/carved_files_inventory.csv", kms_key_arn, "text/csv",
            )
        for md_path in markdown_files:
            upload_file(s3_client, md_path, dest_bucket, f"{base_s3_prefix}/markdown/{md_path.name}", kms_key_arn, "text/markdown; charset=utf-8")

        logger.info("dfirbaboon pipeline finished (%s). Artifacts archived in s3://%s/", coc_metadata["status"], dest_bucket)
        return 0

    except Exception as exc:  # noqa: BLE001 - recorded in the vault, then re-reported via exit code
        logger.exception("dfirbaboon worker failed: %s", exc)
        if dest_bucket and coc_metadata:
            try:
                coc_metadata.update({"status": "failed", "error": f"{type(exc).__name__}: {exc}", "processed_timestamp_utc": utc_now()})
                write_and_upload_coc(s3_client, coc_metadata, work_dir, dest_bucket, evidence_filename, kms_key_arn)
            except Exception:  # noqa: BLE001
                logger.exception("Could not upload failure manifest.")
        return 2 if isinstance(exc, (ClientError, BotoCoreError)) else 1
    finally:
        if work_dir.exists() and str(work_dir).startswith("/tmp"):
            for child in work_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
