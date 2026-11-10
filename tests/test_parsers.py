"""Unit tests for the dfirbaboon ForensicParser plugin architecture."""

import shutil
import tempfile
import unittest
from pathlib import Path

try:
    from worker.config import WorkerConfig
    from worker.parsers.base import BaseParser, ParserContext, ParserFactory, ParserResult
except ImportError:
    from config import WorkerConfig
    from parsers.base import BaseParser, ParserContext, ParserFactory, ParserResult


class MockParser(BaseParser):
    """Mock implementation for testing BaseParser execution contracts."""

    def get_parser_name(self) -> str:
        return "mock_parser"

    def get_parser_type(self) -> str:
        return "test"

    def validate(self, evidence_path: Path) -> bool:
        return evidence_path.name.endswith(".raw")

    def parse(self, context: ParserContext) -> ParserResult:
        if "force_fail" in context.shared_state:
            raise RuntimeError("Induced failure for testing")

        out_file = context.scratch_dir / "mock_output.txt"
        out_file.write_text("parsed content", encoding="utf-8")

        return ParserResult(
            parser_name=self.get_parser_name(),
            parser_type=self.get_parser_type(),
            status="SUCCESS",
            output_files=[out_file],
            metrics={"records": 42},
        )


class TestParserArchitecture(unittest.TestCase):
    """Test suite for the plugin parser architecture and registry."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_parser_factory_registration(self) -> None:
        """Verify parsers can be registered and instantiated through the factory."""
        ParserFactory.register("mock_parser", MockParser)
        self.assertIn("mock_parser", ParserFactory.get_registered_parsers())

        config = WorkerConfig()
        parser = ParserFactory.create_parser("mock_parser", config)
        self.assertIsInstance(parser, MockParser)
        self.assertEqual(parser.get_parser_name(), "mock_parser")
        self.assertEqual(parser.get_parser_type(), "test")

    def test_parser_factory_missing_raises(self) -> None:
        """Verify attempting to create an unregistered parser raises KeyError."""
        with self.assertRaises(KeyError):
            ParserFactory.create_parser("non_existent", WorkerConfig())

    def test_safe_parse_success(self) -> None:
        """Verify safe_parse executes successfully and measures elapsed time."""
        evidence = self.tmp_dir / "test.raw"
        evidence.write_bytes(b"dummy evidence")
        scratch = self.tmp_dir / "scratch"
        scratch.mkdir()

        config = WorkerConfig()
        parser = MockParser(config)
        context = ParserContext(
            incident_id="INC00001",
            evidence_file="test.raw",
            evidence_path=evidence,
            scratch_dir=scratch,
            config=config,
        )

        result = parser.safe_parse(context)
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.parser_name, "mock_parser")
        self.assertGreaterEqual(result.duration_seconds, 0.0)
        self.assertEqual(len(result.output_files), 1)
        self.assertEqual(result.output_files[0].read_text(encoding="utf-8"), "parsed content")
        self.assertEqual(result.metrics["records"], 42)
        self.assertEqual(len(result.errors), 0)

    def test_safe_parse_validation_skip(self) -> None:
        """Verify safe_parse skips execution when validation returns False."""
        evidence = self.tmp_dir / "test.vmdk"  # Not .raw
        evidence.write_bytes(b"dummy")

        config = WorkerConfig()
        parser = MockParser(config)
        context = ParserContext(
            incident_id="INC00001",
            evidence_file="test.vmdk",
            evidence_path=evidence,
            scratch_dir=self.tmp_dir,
            config=config,
        )

        result = parser.safe_parse(context)
        self.assertEqual(result.status, "SKIPPED")
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("not applicable", result.warnings[0])

    def test_safe_parse_exception_containment(self) -> None:
        """Verify safe_parse catches and records unhandled exceptions without crashing."""
        evidence = self.tmp_dir / "test.raw"
        evidence.write_bytes(b"dummy")

        config = WorkerConfig()
        parser = MockParser(config)
        context = ParserContext(
            incident_id="INC00001",
            evidence_file="test.raw",
            evidence_path=evidence,
            scratch_dir=self.tmp_dir,
            config=config,
            shared_state={"force_fail": True},
        )

        result = parser.safe_parse(context)
        self.assertEqual(result.status, "FAILED")
        self.assertEqual(len(result.errors), 1)
        self.assertIn("Induced failure for testing", result.errors[0])
        self.assertGreaterEqual(result.duration_seconds, 0.0)

    def test_builtin_parsers_registered(self) -> None:
        """Verify all built-in pipeline parsers (tsk, carving, yara) are registered in the factory."""
        try:
            import worker.parsers  # noqa: F401
        except ImportError:
            import parsers  # noqa: F401

        registered = ParserFactory.get_registered_parsers()
        self.assertIn("tsk", registered)
        self.assertIn("carving", registered)
        self.assertIn("yara", registered)

    def test_yara_scanner_custom_rules_loading(self) -> None:
        """Verify YaraScanner loads custom .yar rules and computes cryptographic ruleset hashes."""
        try:
            from worker.parsers.yara_scanner import YaraScanner
        except ImportError:
            from parsers.yara_scanner import YaraScanner

        rules_dir = self.tmp_dir / "custom_rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "custom_test.yar"
        rule_file.write_text(
            'rule Custom_Test_Marker {\n'
            '    strings:\n'
            '        $a = "MALICIOUS_C2_STRING"\n'
            '    condition:\n'
            '        $a\n'
            '}\n',
            encoding="utf-8",
        )

        scanner = YaraScanner(custom_rules_dir=str(rules_dir))
        self.assertIn("builtin_dfir", scanner.ruleset_hashes)
        self.assertIn("custom_test.yar", scanner.ruleset_hashes)
        self.assertGreaterEqual(scanner.rules_count, 7)


if __name__ == "__main__":
    unittest.main()
