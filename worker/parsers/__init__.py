"""Forensic parsing modules and plugin interfaces for the dfirbaboon worker pipeline."""

try:
    from .base import BaseParser, ParserContext, ParserFactory, ParserResult
    from .carving import CarvingEngine, CarvingForensicParser, CarvingResult, run_carving
    from .md_exporter import MarkdownExporter
    from .tsk_parser import TSKAnalysisResult, TSKForensicParser, TSKParser
    from .yara_scanner import YaraAnalysisResult, YaraForensicParser, YaraScanner
except ImportError:
    from parsers.base import BaseParser, ParserContext, ParserFactory, ParserResult
    from parsers.carving import CarvingEngine, CarvingForensicParser, CarvingResult, run_carving
    from parsers.md_exporter import MarkdownExporter
    from parsers.tsk_parser import TSKAnalysisResult, TSKForensicParser, TSKParser
    from parsers.yara_scanner import YaraAnalysisResult, YaraForensicParser, YaraScanner

__all__ = [
    "BaseParser",
    "ParserContext",
    "ParserResult",
    "ParserFactory",
    "TSKParser",
    "TSKForensicParser",
    "TSKAnalysisResult",
    "YaraScanner",
    "YaraForensicParser",
    "YaraAnalysisResult",
    "MarkdownExporter",
    "CarvingEngine",
    "CarvingForensicParser",
    "CarvingResult",
    "run_carving",
]
