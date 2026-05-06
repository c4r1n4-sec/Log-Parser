"""Tests for rule-focused reporting and optional generic hit output."""

from __future__ import annotations

import csv
from pathlib import Path

from app.core.jobs.run_scan import ScanOptions, run_scan
from app.core.util.config import ExtractionLimits


def test_generic_hits_are_optional_and_not_counted_as_findings(tmp_path: Path) -> None:
    log_path = tmp_path / "noisy.log"
    log_path.write_text("\n".join(["error timeout proxy"] * 50), encoding="utf-8")
    output_dir = tmp_path / "out"

    result = run_scan([str(log_path)], str(output_dir), ScanOptions(limits=_limits()))

    assert result.hit_count == 0
    assert not (output_dir / "generic_hits.csv").exists()
    assert _read_csv(output_dir / "all_hits.csv") == []
    report_html = (output_dir / "triage_report.html").read_text(encoding="utf-8")
    assert "GENERIC_SEARCH" not in report_html


def test_generic_hits_csv_is_written_only_when_enabled(tmp_path: Path) -> None:
    log_path = tmp_path / "noisy.log"
    log_path.write_text("error timeout proxy\n", encoding="utf-8")
    output_dir = tmp_path / "out"

    result = run_scan(
        [str(log_path)],
        str(output_dir),
        ScanOptions(limits=_limits(), include_generic_hits=True),
    )

    assert result.hit_count == 0
    assert result.generic_hits_csv == output_dir.resolve() / "generic_hits.csv"
    generic_hits = _read_csv(output_dir / "generic_hits.csv")
    assert {hit["rule_id"] for hit in generic_hits} == {"GENERIC_SEARCH"}
    assert _read_csv(output_dir / "all_hits.csv") == []


def test_duplicate_rule_hits_are_suppressed_in_summary_and_html_is_capped(tmp_path: Path) -> None:
    log_path = tmp_path / "ReporterLog-test.log"
    repeated_line = "ERROR AntibodyMetadataLookup Execution Timeout Expired"
    log_path.write_text("\n".join([repeated_line] * 40), encoding="utf-8")
    output_dir = tmp_path / "out"

    result = run_scan(
        [str(log_path)],
        str(output_dir),
        ScanOptions(limits=_limits(), max_examples_per_rule_in_report=2),
    )

    assert result.hit_count == 1
    findings = _read_csv(output_dir / "findings_by_rule.csv")
    assert findings[0]["rule_id"] == "APPC_SQL_TIMEOUT"
    assert findings[0]["hit_count"] == "1"
    all_hits = _read_csv(output_dir / "all_hits.csv")
    assert len([hit for hit in all_hits if hit["rule_id"] == "APPC_SQL_TIMEOUT"]) == 40
    html = (output_dir / "triage_report.html").read_text(encoding="utf-8")
    assert "Additional hits omitted from report. See all_hits.csv." not in html


def test_html_report_caps_distinct_examples_per_rule(tmp_path: Path) -> None:
    log_path = tmp_path / "ReporterLog-test.log"
    log_path.write_text(
        "\n".join(f"AntibodyMetadataLookup Execution Timeout Expired {i}" for i in range(5)),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"

    run_scan(
        [str(log_path)],
        str(output_dir),
        ScanOptions(limits=_limits(), max_examples_per_rule_in_report=2),
    )

    html = (output_dir / "triage_report.html").read_text(encoding="utf-8")
    assert html.count("rule_id:</strong> APPC_SQL_TIMEOUT") == 2
    assert "Additional hits omitted from report. See all_hits.csv." in html


def test_procmon_pml_oversize_warning_is_specific(tmp_path: Path) -> None:
    pml_path = tmp_path / "capture.pml"
    pml_path.write_bytes(b"PML" + b"\0" * 20)
    output_dir = tmp_path / "out"

    result = run_scan(
        [str(pml_path)],
        str(output_dir),
        ScanOptions(
            limits=ExtractionLimits(
                max_archive_depth=1,
                max_total_extracted_bytes=1024,
                max_single_file_bytes=4,
            )
        ),
    )

    assert any("ProcMon PML binary was not fully decoded" in warning for warning in result.warnings)
    assert any("File exceeds warning threshold" in warning for warning in result.warnings)
    row = _read_csv(output_dir / "artifact_coverage.csv")[0]
    assert row["artifact_family"] == "procmon_pml"
    assert row["review_mode"] == "binary-string-scanned"
    assert "ProcMon PML binary was not fully decoded" in row["limitations"]
    assert "File exceeds warning threshold" in row["limitations"]


def _limits() -> ExtractionLimits:
    return ExtractionLimits(
        max_archive_depth=5,
        max_total_extracted_bytes=10 * 1024 * 1024,
        max_single_file_bytes=1024 * 1024,
    )


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))
