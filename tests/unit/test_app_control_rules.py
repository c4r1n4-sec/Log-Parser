"""Unit tests for Carbon Black App Control classification and rule hits."""

from __future__ import annotations

import csv
from pathlib import Path

from app.core.jobs.scan_job import run_ingestion_scan
from app.core.util.config import ExtractionLimits


def test_reporter_sql_timeout_rule(tmp_path: Path) -> None:
    log_path = tmp_path / "reporter.log"
    log_path.write_text(
        "ReporterService started\n"
        "AntibodyMetadataLookup failed\n"
        "Execution Timeout Expired while running GetAntibodiesWithMissingMetadata\n",
        encoding="utf-8",
    )

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_limits())
    hits = _read_csv(result.all_hits_csv)
    coverage = _coverage_by_name(result.coverage_csv, "reporter.log")
    hit = _hit_by_rule(hits, "APPC_SQL_TIMEOUT")

    assert coverage["artifact_family"] == "reporter_log"
    assert hit["product"] == "Carbon Black App Control"
    assert hit["severity"] == "High"
    assert hit["issue_category"] == "Database timeout"
    assert "KB candidate 291435" in hit["kb_candidate_ids"]
    assert hit["rule_id"] == "APPC_SQL_TIMEOUT"


def test_winhttp_getsslerror_rule(tmp_path: Path) -> None:
    log_path = tmp_path / "trace.bt9"
    log_path.write_text(
        "trace.bt9 Server Communication\n"
        "GetSslError[16] WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID\n",
        encoding="utf-8",
    )

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_limits())
    hits = _read_csv(result.all_hits_csv)
    coverage = _coverage_by_name(result.coverage_csv, "trace.bt9")
    hit = _hit_by_rule(hits, "APPC_CERT_CN_MISMATCH")

    assert coverage["artifact_family"] == "agent_trace_bt9"
    assert hit["component"] == "Agent TLS"
    assert "KB candidate 290752" in hit["kb_candidate_ids"]


def test_tamper_rule(tmp_path: Path) -> None:
    log_path = tmp_path / "agent.log"
    log_path.write_text(
        "trace.bt9 Server Communication\nAgent tampering prevented by Tamper Protection\n",
        encoding="utf-8",
    )

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_limits())
    hit = _hit_by_rule(_read_csv(result.all_hits_csv), "APPC_TAMPER")

    assert hit["severity"] == "Medium"
    assert hit["issue_category"] == "Tamper protection"
    assert "KB candidate 288536" in hit["kb_candidate_ids"]


def test_appcwebserver_rule(tmp_path: Path) -> None:
    log_path = tmp_path / "analysis.txt"
    log_path.write_text(
        "CB Analysis Script\n"
        "App Control Server Schema Active Hosts SQL Server AppCWebServer\n"
        "Cannot find the server principal AppCWebServer\n",
        encoding="utf-8",
    )

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_limits())
    hits = _read_csv(result.all_hits_csv)
    coverage = _coverage_by_name(result.coverage_csv, "analysis.txt")
    hit = _hit_by_rule(hits, "APPC_SQL_ROLE_DSN_APPCWEBSERVER")

    assert coverage["artifact_family"] == "cb_analysis_output"
    assert hit["component"] == "SQL Server / AppCWebServer"
    assert "KB candidate 436182" in hit["kb_candidate_ids"]


def test_kernel_assertion_is_low_severity(tmp_path: Path) -> None:
    log_path = tmp_path / "server.log"
    log_path.write_text(
        "ServerLog Carbon Black App Control\nkernel assertions FailureId[778]\n",
        encoding="utf-8",
    )

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_limits())
    hit = _hit_by_rule(_read_csv(result.all_hits_csv), "APPC_KERNEL_ASSERTION")

    assert hit["severity"] == "Low"
    assert hit["issue_category"] == "Kernel assertion"
    assert "KB candidate 288544" in hit["kb_candidate_ids"]


def _limits() -> ExtractionLimits:
    return ExtractionLimits(
        max_archive_depth=5,
        max_total_extracted_bytes=10 * 1024 * 1024,
        max_single_file_bytes=1024 * 1024,
    )


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))


def _coverage_by_name(path: Path, name: str) -> dict[str, str]:
    return next(row for row in _read_csv(path) if row["artifact_path"].endswith(name))


def _hit_by_rule(hits: list[dict[str, str]], rule_id: str) -> dict[str, str]:
    return next(hit for hit in hits if hit["rule_id"] == rule_id)
