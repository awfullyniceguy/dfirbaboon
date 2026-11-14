"""Unit tests for dfirbaboon WorkerConfig."""

import os
import unittest
from unittest.mock import patch

try:
    from worker.config import WorkerConfig
except ImportError:
    from config import WorkerConfig


class TestWorkerConfig(unittest.TestCase):
    """Test suite for WorkerConfig validation and environment parsing."""

    def test_default_config(self) -> None:
        """Verify default WorkerConfig parameters match production expectations."""
        config = WorkerConfig()
        self.assertEqual(config.project_prefix, "dfirbaboon")
        self.assertEqual(config.forensic_mode, "simple")
        self.assertFalse(config.is_compliance_mode)
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(config.aws_region, "us-east-1")
        self.assertEqual(config.dfir_tool_timeout_sec, 3600)
        self.assertEqual(config.retention_days, 365)
        self.assertTrue(config.enable_carving)
        self.assertTrue(config.enable_yara)
        self.assertEqual(config.s3_chunk_size_bytes, 16 * 1024 * 1024)
        self.assertEqual(config.parsers_enabled, ["tsk", "carving", "yara"])
        self.assertEqual(config.yara_rules_dir, "/app/rules")

    def test_config_from_env_overrides(self) -> None:
        """Verify environment variables correctly override default configurations."""
        env = {
            "PROJECT_PREFIX": "customdfir",
            "FORENSIC_MODE": "compliance",
            "LOG_LEVEL": "DEBUG",
            "AWS_REGION": "us-west-2",
            "AWS_ACCOUNT_ID": "123456789012",
            "KMS_KEY_ARN": "arn:aws:kms:us-west-2:123456789012:key/test-key-id",
            "BATCH_SCRATCH_DIR": "/work/scratch",
            "DFIR_TOOL_TIMEOUT_SEC": "7200",
            "RETENTION_DAYS": "730",
            "ENABLE_CARVING": "false",
            "ENABLE_YARA": "0",
            "PARSERS_ENABLED": "tsk,yara",
        }
        with patch.dict(os.environ, env, clear=True):
            config = WorkerConfig.from_env()
            self.assertEqual(config.project_prefix, "customdfir")
            self.assertEqual(config.forensic_mode, "compliance")
            self.assertTrue(config.is_compliance_mode)
            self.assertEqual(config.log_level, "DEBUG")
            self.assertEqual(config.aws_region, "us-west-2")
            self.assertEqual(config.aws_account_id, "123456789012")
            self.assertEqual(config.kms_key_arn, "arn:aws:kms:us-west-2:123456789012:key/test-key-id")
            self.assertEqual(config.output_directory, "/work/scratch")
            self.assertEqual(config.dfir_tool_timeout_sec, 7200)
            self.assertEqual(config.retention_days, 730)
            self.assertFalse(config.enable_carving)
            self.assertFalse(config.enable_yara)
            self.assertEqual(config.parsers_enabled, ["tsk", "yara"])

    def test_config_validation_errors(self) -> None:
        """Verify invalid configuration options trigger appropriate ValueErrors."""
        with self.assertRaises(ValueError):
            WorkerConfig(forensic_mode="invalid")

        with self.assertRaises(ValueError):
            WorkerConfig(dfir_tool_timeout_sec=0)

        with self.assertRaises(ValueError):
            WorkerConfig(retention_days=-1)

        with self.assertRaises(ValueError):
            WorkerConfig(s3_chunk_size_bytes=512)

        with self.assertRaises(ValueError):
            WorkerConfig(output_directory="")

    def test_resolve_vault_bucket_default(self) -> None:
        """Verify default template resolution for incident vault bucket."""
        config = WorkerConfig(project_prefix="dfirbaboon")
        bucket = config.resolve_vault_bucket_name("INC-1002", "123456789012")
        self.assertEqual(bucket, "dfirbaboon-inc-1002-123456789012")

    def test_resolve_vault_bucket_override(self) -> None:
        """Verify explicit bucket override bypasses templating."""
        config = WorkerConfig(vault_bucket_override="corp-central-forensic-vault")
        bucket = config.resolve_vault_bucket_name("INC-1002", "123456789012")
        self.assertEqual(bucket, "corp-central-forensic-vault")

    def test_resolve_vault_bucket_custom_template(self) -> None:
        """Verify custom enterprise template interpolation."""
        config = WorkerConfig(
            vault_bucket_template="secops-vault-{region}-{incident_id}",
            aws_region="us-west-2",
        )
        bucket = config.resolve_vault_bucket_name("INC_9999", "111222333444")
        self.assertEqual(bucket, "secops-vault-us-west-2-inc-9999")

    def test_resolve_vault_key(self) -> None:
        """Verify vault key resolution with and without prefix."""
        # Default empty prefix
        config = WorkerConfig()
        key = config.resolve_vault_key("raw_evidence/disk.raw", "INC-500")
        self.assertEqual(key, "raw_evidence/disk.raw")

        # Enterprise shared lake prefix with template variables
        config_prefixed = WorkerConfig(vault_prefix="forensics/{incident_id}/evidence")
        key = config_prefixed.resolve_vault_key("raw_evidence/disk.raw", "INC-500")
        self.assertEqual(key, "forensics/INC-500/evidence/raw_evidence/disk.raw")

    def test_config_from_env_byo_settings(self) -> None:
        """Verify enterprise BYO environment variables parse properly."""
        env = {
            "CREATE_VAULT_BUCKET": "false",
            "VAULT_BUCKET": "pre-vended-forensic-lake",
            "VAULT_PREFIX": "cases/{incident_id}",
        }
        with patch.dict(os.environ, env, clear=True):
            config = WorkerConfig.from_env()
            self.assertFalse(config.create_vault_bucket)
            self.assertEqual(config.vault_bucket_override, "pre-vended-forensic-lake")
            self.assertEqual(config.vault_prefix, "cases/{incident_id}")


if __name__ == "__main__":
    unittest.main()
