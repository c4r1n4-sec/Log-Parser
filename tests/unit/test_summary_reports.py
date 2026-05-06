"""Unit tests for derived findings and triage reports."""

from __future__ import annotations

import csv
from pathlib import Path

from app.core.jobs.scan_job import run_ingestion_scan
from app.core.util.config import ExtractionLimits


def test_missing_reporterlog_checklist(tmp_path: Path) -> None:
    log_path = tmp_path / "server.log"
    log_path.write_text("ServerLog Carbon Black App Control\nservices.bit9.com\n", encoding="utf-8")

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_limits())
    checklist = result.missing_evidence_checklist_txt.read_text(encoding="utf-8")

    assert result.missing_evidence_checklist_txt.exists()
    assert "CDC / File Reputation missing evidence" in checklist
    assert "ReporterLog" in checklist
    assert "confirmed root cause" not in checklist.lower()


def test_sql_timeout_with_missing_sqltrace(tmp_path: Path) -> None:
    log_path = tmp_path / "reporter.log"
    log_path.write_text(
        "ReporterService\nExecution Timeout Expired\nAntibodyMetadataLookup\n", encoding="utf-8"
    )

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_limits())
    findings = _read_csv(result.findings_by_rule_csv)
    checklist = result.missing_evidence_checklist_txt.read_text(encoding="utf-8")
    report_txt = result.triage_report_txt.read_text(encoding="utf-8")

    sql_finding = next(row for row in findings if row["rule_id"] == "APPC_SQL_TIMEOUT")
    assert sql_finding["required_evidence_status"].startswith("Observed evidence present")
    assert "SQLTrace" in checklist
    assert "No SQLTrace found" in report_txt


def test_negative_getsslerror_search(tmp_path: Path) -> None:
    trace_path = tmp_path / "trace.bt9"
    trace_path.write_text("trace.bt9\nServer Communication\nWaitForResponse\n", encoding="utf-8")

    result = run_ingestion_scan([trace_path], output_dir=tmp_path / "output", limits=_limits())
    report_txt = result.triage_report_txt.read_text(encoding="utf-8")

    assert "No GetSslError found" in report_txt
    assert "No GetWinHttpError found" in report_txt


def test_html_report_generation(tmp_path: Path) -> None:
    log_path = tmp_path / "agent.log"
    log_path.write_text("trace.bt9\nAgent tampering prevented\n", encoding="utf-8")

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_limits())
    html = result.triage_report_html.read_text(encoding="utf-8")

    assert result.triage_report_html.exists()
    assert "<!doctype html>" in html
    assert "High App Control findings" in html
    assert "Raw hit appendix" not in html
    assert "APPC_TAMPER" in html
    assert "Confirmed root cause" not in html


def test_txt_report_generation(tmp_path: Path) -> None:
    log_path = tmp_path / "server.log"
    log_path.write_text("ServerLog Carbon Black App Control\nkernel assertions\n", encoding="utf-8")

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_limits())
    report = result.triage_report_txt.read_text(encoding="utf-8")

    assert result.triage_report_txt.exists()
    assert "Scan summary" in report
    assert "Low findings" not in report
    findings = _read_csv(result.findings_by_rule_csv)
    assert any(row["rule_id"] == "APPC_KERNEL_ASSERTION" for row in findings)
    assert "Observed evidence" in report or "observed evidence" in report
    assert "Confirmed root cause" not in report


def _limits() -> ExtractionLimits:
    return ExtractionLimits(
        max_archive_depth=5,
        max_total_extracted_bytes=10 * 1024 * 1024,
        max_single_file_bytes=1024 * 1024,
    )


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))
