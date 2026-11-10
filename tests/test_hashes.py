"""Unit tests for cryptographic acquisition verification and dual-hashing."""

import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Mock AWS boto3 if not installed in current environment
for mod in ["boto3", "boto3.s3", "boto3.s3.transfer", "botocore", "botocore.config", "botocore.exceptions"]:
    if mod not in sys.modules:
        try:
            __import__(mod)
        except ImportError:
            sys.modules[mod] = MagicMock()

try:
    from worker.entrypoint import hash_file, retrieve_acquisition_hashes
except ImportError:
    from entrypoint import hash_file, retrieve_acquisition_hashes


class TestCryptographicHashes(unittest.TestCase):
    """Test suite for dual-hashing and acquisition verification."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_hash_file(self) -> None:
        """Verify dual SHA-256 and MD5 hashes are computed correctly over disk data."""
        test_file = self.tmp_dir / "sample.raw"
        data = b"FORENSIC_EVIDENCE_SAMPLE_FOR_TESTING_123456" * 1024
        test_file.write_bytes(data)

        expected_sha256 = hashlib.sha256(data).hexdigest()
        expected_md5 = hashlib.md5(data).hexdigest()

        hashes = hash_file(test_file)
        self.assertEqual(hashes["sha256"], expected_sha256)
        self.assertEqual(hashes["md5"], expected_md5)

    def test_retrieve_acquisition_hashes_from_metadata(self) -> None:
        """Verify retrieval of acquisition hashes from S3 object metadata."""
        mock_s3 = MagicMock()
        metadata = {
            "acquisition-sha256": "fc38dd500b41cb397e8a09add383610bb7934fdadda289d82c9a838fed85e99d",
            "acquisition-md5": "526817e924bb80b292a3e26157278d0c",
        }

        sha256, md5, source = retrieve_acquisition_hashes(
            mock_s3, "test-bucket", "INC10001/disk.raw", metadata
        )
        self.assertEqual(sha256, "fc38dd500b41cb397e8a09add383610bb7934fdadda289d82c9a838fed85e99d")
        self.assertEqual(md5, "526817e924bb80b292a3e26157278d0c")
        self.assertEqual(source, "s3_object_metadata")


if __name__ == "__main__":
    unittest.main()
