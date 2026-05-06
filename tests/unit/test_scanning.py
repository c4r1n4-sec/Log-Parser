"""Unit tests for text and binary generic search scanning."""

from __future__ import annotations

from pathlib import Path

from app.core.scan.search import scan_binary_file, scan_text_file


def test_utf8_log_scanning_produces_line_numbered_hit(tmp_path: Path) -> None:
    log_path = tmp_path / "sensor.log"
    log_path.write_text("startup ok\nerror connecting to proxy\nfinished\n", encoding="utf-8")

    stats = scan_text_file(log_path)

    assert any(hit.matched_text == "error" and hit.line_number == "2" for hit in stats.hits)
    assert stats.encoding == "utf-8"
    assert stats.lines_or_rows_scanned == 3
    assert stats.review_mode == "stream-scanned"
    assert stats.decoded_successfully is True


def test_utf16_log_scanning_uses_bom_encoding(tmp_path: Path) -> None:
    log_path = tmp_path / "utf16.log"
    log_path.write_text("first\nfailed service start\n", encoding="utf-16")

    stats = scan_text_file(log_path)

    assert any(hit.matched_text == "failed" and hit.line_number == "2" for hit in stats.hits)
    assert stats.encoding == "utf-16"
    assert stats.decoded_successfully is True


def test_malformed_text_uses_latin1_fallback(tmp_path: Path) -> None:
    log_path = tmp_path / "malformed.log"
    log_path.write_bytes(b"before\nerror with undefined cp1252 byte \x81\nafter\n")

    stats = scan_text_file(log_path)

    assert any(hit.matched_text == "error" and hit.line_number == "2" for hit in stats.hits)
    assert stats.encoding == "latin-1"
    assert stats.lines_or_rows_scanned == 3


def test_binary_string_hit_records_byte_offset(tmp_path: Path) -> None:
    binary_path = tmp_path / "payload.bin"
    binary_path.write_bytes(b"\x00\x01prefix services.bit9.com timeout suffix\x00\xff")

    stats = scan_binary_file(binary_path)

    assert any(
        hit.matched_text == "services.bit9.com"
        and hit.byte_offset
        and hit.match_type == "ascii-string"
        for hit in stats.hits
    )
    assert stats.review_mode == "binary-string-scanned"
    assert stats.encoding == "binary"
    assert stats.bytes_scanned == binary_path.stat().st_size


def test_context_line_capture(tmp_path: Path) -> None:
    log_path = tmp_path / "context.log"
    log_path.write_text(
        "before one\nbefore two\nblocked by policy\nafter one\nafter two\nafter three\n",
        encoding="utf-8",
    )

    stats = scan_text_file(log_path)
    hit = next(hit for hit in stats.hits if hit.matched_text == "blocked")

    assert hit.line_number == "3"
    assert hit.raw_line == "blocked by policy"
    assert hit.context_before == "before one\nbefore two"
    assert hit.context_after == "after one\nafter two"
