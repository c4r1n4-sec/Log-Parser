"""Integration test with a small synthetic App Control evidence bundle."""

from __future__ import annotations

import csv
import zipfile
from pathlib import Path

from app.core.jobs.scan_job import run_ingestion_scan
from app.core.util.config import ExtractionLimits


def test_synthetic_app_control_bundle_reports(tmp_path: Path) -> None:
    bundle = tmp_path / "synthetic_bundle"
    bundle.mkdir()

    (bundle / "ReporterLog.log").write_text(
        "ReporterService\nAntibodyMetadataLookup\nExecution Timeout Expired\n",
        encoding="utf-8",
    )
    (bundle / "trace.bt9").write_text(
        "trace.bt9\nServer Communication\nGetSslError[16]\n",
        encoding="utf-8",
    )
    (bundle / "ServerLog.bt9").write_text(
        "ServerLog Carbon Black App Control\nCannot find the server principal AppCWebServer\n",
        encoding="utf-8",
    )
    (bundle / "payload.bin").write_bytes(b"\x00binary printable services.bit9.com timeout\x00")

    inner_zip = bundle / "inner.zip"
    with zipfile.ZipFile(inner_zip, "w") as archive:
        archive.writestr("nested.log", "nested error line\n")
    outer_zip = bundle / "outer.zip"
    with zipfile.ZipFile(outer_zip, "w") as archive:
        archive.write(inner_zip, "archives/inner.zip")

    result = run_ingestion_scan([bundle], output_dir=tmp_path / "output", limits=_limits())

    for path in (
        result.coverage_csv,
        result.all_hits_csv,
        result.findings_by_rule_csv,
        result.findings_by_file_csv,
        result.missing_evidence_checklist_txt,
        result.triage_report_html,
        result.triage_report_txt,
    ):
        assert path.exists(), path

    hits = _read_csv(result.all_hits_csv)
    coverage = _read_csv(result.coverage_csv)
    hit_rule_ids = {hit["rule_id"] for hit in hits}
    report_txt = result.triage_report_txt.read_text(encoding="utf-8")
    checklist = result.missing_evidence_checklist_txt.read_text(encoding="utf-8")

    assert "APPC_SQL_TIMEOUT" in hit_rule_ids
    assert "APPC_CERT_CN_MISMATCH" in hit_rule_ids
    assert "APPC_SQL_ROLE_DSN_APPCWEBSERVER" in hit_rule_ids
    assert any(row["artifact_path"].endswith("nested.log") for row in coverage)
    assert "Missing Evidence Checklist" in checklist
    assert "No SQLTrace found" in report_txt
    assert "Negative searches" in report_txt
    assert "Confirmed root cause" not in report_txt


def _limits() -> ExtractionLimits:
    return ExtractionLimits(
        max_archive_depth=5,
        max_total_extracted_bytes=10 * 1024 * 1024,
        max_single_file_bytes=1024 * 1024,
    )


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))
