"""Unit tests for optional decoder discovery and graceful fallback."""

from __future__ import annotations

import csv
import subprocess
from pathlib import Path

from app.core.decode import helpers
from app.core.jobs.scan_job import run_ingestion_scan
from app.core.util.config import ExtractionLimits


def test_tshark_missing_pcap_falls_back_to_binary_scan(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(helpers, "find_tshark", lambda: None)
    pcap_path = tmp_path / "capture.pcapng"
    pcap_path.write_bytes(b"\x0a\x0d\x0d\x0aprefix services.bit9.com timeout suffix\x00")

    result = run_ingestion_scan([pcap_path], output_dir=tmp_path / "output", limits=_limits())
    coverage = _coverage_by_name(result.coverage_csv, "capture.pcapng")
    hits = _read_csv(result.all_hits_csv)

    assert coverage["artifact_family"] == "pcapng"
    assert coverage["decoder_used"] == "tshark"
    assert coverage["decoder_status"] == "specialized-tool-unavailable"
    assert coverage["review_mode"] == "binary-string-scanned"
    assert any(hit["matched_text"] == "services.bit9.com" for hit in hits)


def test_7z_missing_is_specialized_tool_unavailable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(helpers, "find_7zip", lambda: None)
    archive_path = tmp_path / "bundle.7z"
    archive_path.write_bytes(b"7z\xbc\xaf\x27\x1c")

    result = run_ingestion_scan([archive_path], output_dir=tmp_path / "output", limits=_limits())
    coverage = _coverage_by_name(result.coverage_csv, "bundle.7z")

    assert coverage["artifact_family"] == "seven_zip"
    assert coverage["decoder_used"] == "7zip"
    assert coverage["decoder_status"] == "specialized-tool-unavailable"


def test_expand_failed_marks_cab_decode_failed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(helpers, "find_expand", lambda: Path("expand.exe"))
    monkeypatch.setattr(
        helpers,
        "_run_tool",
        lambda command: subprocess.CompletedProcess(
            command, returncode=1, stdout="", stderr="fail"
        ),
    )
    cab_path = tmp_path / "archive.cab"
    cab_path.write_bytes(b"MSCF placeholder")

    result = run_ingestion_scan([cab_path], output_dir=tmp_path / "output", limits=_limits())
    coverage = _coverage_by_name(result.coverage_csv, "archive.cab")

    assert coverage["artifact_family"] == "cab"
    assert coverage["decoder_used"] == "expand.exe"
    assert coverage["decoder_status"] == "decode-failed"


def test_tracerpt_missing_records_exact_etl_limitation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(helpers, "find_tracerpt", lambda: None)
    etl_path = tmp_path / "trace.etl"
    etl_path.write_bytes(b"ETL timeout strings")

    result = run_ingestion_scan([etl_path], output_dir=tmp_path / "output", limits=_limits())
    coverage = _coverage_by_name(result.coverage_csv, "trace.etl")

    assert coverage["artifact_family"] == "etl"
    assert coverage["decoder_used"] == "tracerpt.exe"
    assert coverage["decoder_status"] == "specialized-tool-unavailable"
    assert coverage["limitations"] == helpers.ETL_LIMITATION


def test_evtx_decode_failed_continues(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(helpers, "find_wevtutil", lambda: Path("wevtutil.exe"))
    monkeypatch.setattr(
        helpers,
        "_run_tool",
        lambda command: subprocess.CompletedProcess(
            command, returncode=2, stdout="", stderr="fail"
        ),
    )
    evtx_path = tmp_path / "events.evtx"
    evtx_path.write_bytes(b"EVTX placeholder")

    result = run_ingestion_scan([evtx_path], output_dir=tmp_path / "output", limits=_limits())
    coverage = _coverage_by_name(result.coverage_csv, "events.evtx")

    assert coverage["artifact_family"] == "evtx"
    assert coverage["decoder_used"] == "wevtutil.exe"
    assert coverage["decoder_status"] == "decode-failed"
    assert result.triage_report_txt.exists()


def test_decoded_pcap_csv_gets_scanned(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(helpers, "find_tshark", lambda: Path("tshark.exe"))

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        stdout = "frame.number,frame.time,dns.qry.name\n1,now,error.services.bit9.com\n"
        return subprocess.CompletedProcess(command, returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(helpers, "_run_tool", fake_run)
    pcap_path = tmp_path / "capture.pcap"
    pcap_path.write_bytes(b"pcap placeholder")

    result = run_ingestion_scan([pcap_path], output_dir=tmp_path / "output", limits=_limits())
    rows = _read_csv(result.coverage_csv)
    hits = _read_csv(result.all_hits_csv)

    assert any(
        row["artifact_path"].endswith(".csv") and row["artifact_family"] == "csv" for row in rows
    )
    assert any(
        hit["matched_text"] == "error" and hit["artifact_path"].endswith(".csv") for hit in hits
    )
    assert (result.workspace / "decoded").exists()


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
