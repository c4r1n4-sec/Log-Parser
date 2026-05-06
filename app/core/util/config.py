"""Configuration loading for the portable application."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.core.util.paths import app_root


@dataclass(frozen=True)
class ReportOptions:
    """Report output controls for noisy optional evidence."""

    include_generic_hits: bool
    max_examples_per_rule_in_report: int
    max_report_raw_line_chars: int
    always_write_partial_reports: bool


@dataclass(frozen=True)
class ExtractionLimits:
    """Safety limits applied while recursively extracting archives."""

    max_archive_depth: int
    max_total_extracted_bytes: int
    max_single_file_bytes: int


@dataclass(frozen=True)
class ScanSettings:
    """Streaming scanner controls for large text and binary artifacts."""

    large_file_warning_bytes: int
    text_stream_chunk_lines: int
    binary_chunk_bytes: int
    binary_overlap_bytes: int
    max_context_chars: int


def load_defaults() -> dict[str, Any]:
    """Load the bundled default configuration from source or portable layout."""
    root = app_root()
    candidates = [
        root / "config" / "defaults.json",
        root / "app" / "config" / "defaults.json",
    ]
    for config_path in candidates:
        if config_path.exists():
            with config_path.open("r", encoding="utf-8") as config_file:
                return json.load(config_file)
    raise FileNotFoundError("Unable to locate defaults.json in portable or source config path.")


def extraction_limits(config: dict[str, Any] | None = None) -> ExtractionLimits:
    """Return archive extraction limits from configuration."""
    defaults = config if config is not None else load_defaults()
    extraction = defaults.get("extraction", {})
    return ExtractionLimits(
        max_archive_depth=int(extraction.get("max_archive_depth", 3)),
        max_total_extracted_bytes=int(extraction.get("max_total_extracted_bytes", 1_073_741_824)),
        max_single_file_bytes=int(extraction.get("max_single_file_bytes", 268_435_456)),
    )


def scan_settings(config: dict[str, Any] | None = None) -> ScanSettings:
    """Return streaming scanner settings from configuration."""
    defaults = config if config is not None else load_defaults()
    scanning = defaults.get("scanning", {})
    extraction = defaults.get("extraction", {})
    return ScanSettings(
        large_file_warning_bytes=int(
            scanning.get(
                "large_file_warning_bytes",
                extraction.get("max_single_file_bytes", 268_435_456),
            )
        ),
        text_stream_chunk_lines=int(scanning.get("text_stream_chunk_lines", 10_000)),
        binary_chunk_bytes=int(scanning.get("binary_chunk_bytes", 8_388_608)),
        binary_overlap_bytes=int(scanning.get("binary_overlap_bytes", 4_096)),
        max_context_chars=int(scanning.get("max_context_chars", 4_000)),
    )


def report_options(config: dict[str, Any] | None = None) -> ReportOptions:
    """Return report options from configuration."""
    defaults = config if config is not None else load_defaults()
    reports = defaults.get("reports", {})
    return ReportOptions(
        include_generic_hits=bool(reports.get("include_generic_hits", False)),
        max_examples_per_rule_in_report=int(
            reports.get(
                "max_examples_per_rule_in_report",
                reports.get("max_report_examples_per_rule", 25),
            )
        ),
        max_report_raw_line_chars=int(reports.get("max_report_raw_line_chars", 2_000)),
        always_write_partial_reports=bool(reports.get("always_write_partial_reports", True)),
    )
