"""Unit tests for simple vs compliance mode behavior in worker entrypoint."""

import sys
import unittest
from unittest.mock import MagicMock

# Mock AWS boto3 if not installed in current environment
for mod in ["boto3", "boto3.s3", "boto3.s3.transfer", "botocore", "botocore.config", "botocore.exceptions"]:
    if mod not in sys.modules:
        try:
            __import__(mod)
        except ImportError:
            sys.modules[mod] = MagicMock()

from botocore.exceptions import ClientError

try:
    from worker.entrypoint import copy_evidence_to_vault, provision_incident_vault_bucket
except ImportError:
    from entrypoint import copy_evidence_to_vault, provision_incident_vault_bucket


class _NotFoundClientError(Exception):
    """Lightweight ClientError stand-in for mocked 404 head_bucket."""

    def __init__(self) -> None:
        super().__init__("Not Found")
        self.response = {"Error": {"Code": "404"}}


class TestForensicModes(unittest.TestCase):
    """Verify simple-forensics mode vs compliance mode S3 vault & lock behavior."""

    def test_provision_vault_simple_mode(self) -> None:
        """Simple mode creates bucket without Object Lock, versioning, or Glacier IR."""
        mock_s3 = MagicMock()
        mock_s3.head_bucket.side_effect = ClientError({"Error": {"Code": "404"}}, "HeadBucket") if isinstance(ClientError, type) else _NotFoundClientError()

        # Ensure ClientError in entrypoint catches our exception when botocore is mocked
        if not isinstance(ClientError, type):
            import worker.entrypoint as ep
            ep.ClientError = _NotFoundClientError  # type: ignore[misc]
            mock_s3.head_bucket.side_effect = _NotFoundClientError()

        provision_incident_vault_bucket(
            mock_s3,
            bucket_name="dfirbaboon-inc10001-123456789012",
            region="us-east-1",
            kms_key_arn="",
            create_bucket=True,
            compliance_mode=False,
        )

        mock_s3.create_bucket.assert_called_once_with(Bucket="dfirbaboon-inc10001-123456789012")
        mock_s3.put_public_access_block.assert_called_once()
        mock_s3.put_bucket_encryption.assert_called_once()
        mock_s3.put_bucket_versioning.assert_not_called()
        mock_s3.put_object_lock_configuration.assert_not_called()
        mock_s3.put_bucket_lifecycle_configuration.assert_not_called()

    def test_provision_vault_compliance_mode(self) -> None:
        """Compliance mode enables Object Lock, versioning, retention, and Glacier IR."""
        mock_s3 = MagicMock()
        if isinstance(ClientError, type):
            mock_s3.head_bucket.side_effect = ClientError({"Error": {"Code": "404"}}, "HeadBucket")
        else:
            import worker.entrypoint as ep
            ep.ClientError = _NotFoundClientError  # type: ignore[misc]
            mock_s3.head_bucket.side_effect = _NotFoundClientError()

        provision_incident_vault_bucket(
            mock_s3,
            bucket_name="dfirbaboon-inc10001-123456789012",
            region="us-east-1",
            kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
            create_bucket=True,
            compliance_mode=True,
            retention_days=365,
        )

        mock_s3.create_bucket.assert_called_once_with(
            Bucket="dfirbaboon-inc10001-123456789012",
            ObjectLockEnabledForBucket=True,
        )
        mock_s3.put_public_access_block.assert_called_once()
        mock_s3.put_bucket_encryption.assert_called_once()
        mock_s3.put_bucket_versioning.assert_called_once()
        mock_s3.put_object_lock_configuration.assert_called_once()
        mock_s3.put_bucket_lifecycle_configuration.assert_called_once()

    def test_copy_evidence_simple_vs_compliance(self) -> None:
        """Simple mode skips GLACIER_IR and Legal Hold; compliance mode enforces both."""
        coc_meta = {"incident_id": "INC10001", "sha256": "abc", "md5": "def"}

        mock_s3_simple = MagicMock()
        copy_evidence_to_vault(
            mock_s3_simple,
            "intake-bucket",
            "INC10001/disk.raw",
            "vault-bucket",
            "disk.raw",
            "",
            coc_meta,
            compliance_mode=False,
        )
        simple_extra = mock_s3_simple.copy.call_args.kwargs["ExtraArgs"]
        self.assertNotIn("StorageClass", simple_extra)
        mock_s3_simple.put_object_legal_hold.assert_not_called()

        mock_s3_comp = MagicMock()
        copy_evidence_to_vault(
            mock_s3_comp,
            "intake-bucket",
            "INC10001/disk.raw",
            "vault-bucket",
            "disk.raw",
            "arn:aws:kms:us-east-1:123456789012:key/test",
            coc_meta,
            compliance_mode=True,
        )
        comp_extra = mock_s3_comp.copy.call_args.kwargs["ExtraArgs"]
        self.assertEqual(comp_extra["StorageClass"], "GLACIER_IR")
        self.assertEqual(comp_extra["ServerSideEncryption"], "aws:kms")
        mock_s3_comp.put_object_legal_hold.assert_called_once()


if __name__ == "__main__":
    unittest.main()
