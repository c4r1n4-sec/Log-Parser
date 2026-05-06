"""Unit tests for text and binary generic search scanning."""

from __future__ import annotations

import csv
from pathlib import Path

from app.core.jobs.scan_job import run_ingestion_scan
from app.core.util.config import ExtractionLimits


def test_utf8_log_scanning_produces_line_numbered_hit(tmp_path: Path) -> None:
    log_path = tmp_path / "sensor.log"
    log_path.write_text("startup ok\nerror connecting to proxy\nfinished\n", encoding="utf-8")

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_test_limits())
    hits = _read_csv(result.all_hits_csv)
    coverage = _coverage_by_name(result.coverage_csv, "sensor.log")

    assert result.all_hits_csv.exists()
    assert any(hit["matched_text"] == "error" and hit["line_number"] == "2" for hit in hits)
    assert coverage["encoding"] == "utf-8"
    assert coverage["lines_or_rows_scanned"] == "3"
    assert coverage["review_mode"] == "stream-scanned"
    assert coverage["decoded_successfully"] == "True"


def test_utf16_log_scanning_uses_bom_encoding(tmp_path: Path) -> None:
    log_path = tmp_path / "utf16.log"
    log_path.write_text("first\nfailed service start\n", encoding="utf-16")

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_test_limits())
    hits = _read_csv(result.all_hits_csv)
    coverage = _coverage_by_name(result.coverage_csv, "utf16.log")

    assert any(hit["matched_text"] == "failed" and hit["line_number"] == "2" for hit in hits)
    assert coverage["encoding"] == "utf-16"
    assert coverage["decoded_successfully"] == "True"


def test_malformed_text_uses_latin1_fallback(tmp_path: Path) -> None:
    log_path = tmp_path / "malformed.log"
    log_path.write_bytes(b"before\nerror with undefined cp1252 byte \x81\nafter\n")

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_test_limits())
    hits = _read_csv(result.all_hits_csv)
    coverage = _coverage_by_name(result.coverage_csv, "malformed.log")

    assert any(hit["matched_text"] == "error" and hit["line_number"] == "2" for hit in hits)
    assert coverage["encoding"] == "latin-1"
    assert coverage["lines_or_rows_scanned"] == "3"


def test_binary_string_hit_records_byte_offset(tmp_path: Path) -> None:
    binary_path = tmp_path / "payload.bin"
    binary_path.write_bytes(b"\x00\x01prefix services.bit9.com timeout suffix\x00\xff")

    result = run_ingestion_scan(
        [binary_path], output_dir=tmp_path / "output", limits=_test_limits()
    )
    hits = _read_csv(result.all_hits_csv)
    coverage = _coverage_by_name(result.coverage_csv, "payload.bin")

    assert any(
        hit["matched_text"] == "services.bit9.com"
        and hit["byte_offset"]
        and hit["match_type"] == "ascii-string"
        for hit in hits
    )
    assert coverage["review_mode"] == "binary-string-scanned"
    assert coverage["encoding"] == "binary"
    assert int(coverage["bytes_scanned"]) == binary_path.stat().st_size


def test_context_line_capture(tmp_path: Path) -> None:
    log_path = tmp_path / "context.log"
    log_path.write_text(
        "before one\nbefore two\nblocked by policy\nafter one\nafter two\nafter three\n",
        encoding="utf-8",
    )

    result = run_ingestion_scan([log_path], output_dir=tmp_path / "output", limits=_test_limits())
    hits = _read_csv(result.all_hits_csv)
    hit = next(hit for hit in hits if hit["matched_text"] == "blocked")

    assert hit["line_number"] == "3"
    assert hit["raw_line"] == "blocked by policy"
    assert hit["context_before"] == "before one\nbefore two"
    assert hit["context_after"] == "after one\nafter two"


def _test_limits() -> ExtractionLimits:
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
