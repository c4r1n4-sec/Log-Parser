"""Unit tests for ingestion, safe extraction, and artifact coverage."""

from __future__ import annotations

import csv
import struct
import subprocess
import zipfile
from pathlib import Path

from app.core.decode import helpers
from app.core.jobs.scan_job import run_ingestion_scan
from app.core.util.config import ExtractionLimits


def test_normal_zip_extraction_writes_artifact_coverage(tmp_path: Path) -> None:
    zip_path = tmp_path / "logs.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("logs/app.log", "hello from carbon black log\n")

    result = run_ingestion_scan([zip_path], output_dir=tmp_path / "output", limits=_test_limits())
    rows = _read_coverage(result.coverage_csv)

    assert result.coverage_csv.exists()
    assert any(row["artifact_family"] == "zip" for row in rows)
    assert any(_norm_path(row["artifact_path"]).endswith("logs/app.log") for row in rows)
    assert any(row["artifact_family"] == "text_log" for row in rows)


def test_nested_zip_extraction(tmp_path: Path) -> None:
    inner_zip = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner_zip, "w") as archive:
        archive.writestr("nested/result.json", '{"status": "ok"}')

    outer_zip = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer_zip, "w") as archive:
        archive.write(inner_zip, "archives/inner.zip")

    result = run_ingestion_scan([outer_zip], output_dir=tmp_path / "output", limits=_test_limits())
    rows = _read_coverage(result.coverage_csv)

    assert any(_norm_path(row["artifact_path"]).endswith("archives/inner.zip") for row in rows)
    assert any(_norm_path(row["artifact_path"]).endswith("nested/result.json") for row in rows)
    assert any(row["artifact_family"] == "json" for row in rows)


def test_zip_slip_path_traversal_is_refused(tmp_path: Path) -> None:
    zip_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../evil.txt", "do not extract")
        archive.writestr("safe/good.log", "safe log")

    output_dir = tmp_path / "output"
    result = run_ingestion_scan([zip_path], output_dir=output_dir, limits=_test_limits())
    rows = _read_coverage(result.coverage_csv)

    assert not (output_dir / "evil.txt").exists()
    assert not (result.workspace.parent / "evil.txt").exists()
    assert any(
        _norm_path(row["artifact_path"]).endswith("unsafe.zip!../evil.txt")
        and row["decoder_status"] == "unsafe-archive-path-refused"
        and row["review_mode"] == "skipped-by-policy"
        for row in rows
    )
    assert any(_norm_path(row["artifact_path"]).endswith("safe/good.log") for row in rows)


def test_unsupported_artifact_is_recorded_as_specialized_tool_unavailable(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(helpers, "find_7zip", lambda: None)
    unsupported = tmp_path / "capture.pcapng"
    unsupported.write_bytes(b"\x0a\x0d\x0d\x0a unsupported decoder placeholder")
    seven_zip = tmp_path / "bundle.7z"
    seven_zip.write_bytes(b"7z\xbc\xaf\x27\x1c")

    result = run_ingestion_scan(
        [unsupported, seven_zip], output_dir=tmp_path / "output", limits=_test_limits()
    )
    rows = _read_coverage(result.coverage_csv)

    pcapng_row = next(row for row in rows if row["artifact_path"].endswith("capture.pcapng"))
    seven_zip_row = next(row for row in rows if row["artifact_path"].endswith("bundle.7z"))
    assert pcapng_row["artifact_family"] == "pcapng"
    assert pcapng_row["review_mode"] == "binary-string-scanned"
    assert pcapng_row["decoder_status"] == "specialized-tool-unavailable"
    assert seven_zip_row["artifact_family"] == "seven_zip"
    assert seven_zip_row["decoder_status"] == "specialized-tool-unavailable"


def test_7z_decode_failed_is_recorded_when_tool_listing_fails(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(helpers, "find_7zip", lambda: Path("7z.exe"))

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, returncode=1, stdout="", stderr="fail")

    monkeypatch.setattr(helpers, "_run_tool", fake_run)
    seven_zip = tmp_path / "bundle.7z"
    seven_zip.write_bytes(b"7z\xbc\xaf\x27\x1c")

    result = run_ingestion_scan([seven_zip], output_dir=tmp_path / "output", limits=_test_limits())
    rows = _read_coverage(result.coverage_csv)

    seven_zip_row = next(row for row in rows if row["artifact_path"].endswith("bundle.7z"))
    assert seven_zip_row["artifact_family"] == "seven_zip"
    assert seven_zip_row["decoder_status"] == "decode-failed"


def test_encrypted_zip_member_is_skipped_and_normal_members_continue(tmp_path: Path) -> None:
    zip_path = tmp_path / "mixed.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("logs/normal.log", "normal log is scanable\n")
        archive.writestr("logs/secret.log", "password required\n")
    _mark_zip_member_encrypted(zip_path, "logs/secret.log")

    result = run_ingestion_scan([zip_path], output_dir=tmp_path / "output", limits=_test_limits())
    rows = _read_coverage(result.coverage_csv)

    assert result.coverage_csv.exists()
    assert any(_norm_path(row["artifact_path"]).endswith("logs/normal.log") for row in rows)
    assert not any(_norm_path(row["artifact_path"]).endswith("/logs/secret.log") for row in rows)

    secret_row = next(
        row
        for row in rows
        if _norm_path(row["artifact_path"]).endswith("mixed.zip!logs/secret.log")
    )
    assert secret_row["review_mode"] == "skipped-password-required"
    assert secret_row["decoder_status"] == "password-required"
    assert (
        secret_row["limitations"]
        == "ZIP member is encrypted/password-protected and was not extracted."
    )

    zip_row = next(row for row in rows if _norm_path(row["artifact_path"]).endswith("mixed.zip"))
    assert zip_row["decoder_status"] == "extracted-with-limitations"
    assert "encrypted/password-protected" in zip_row["limitations"]


def _test_limits() -> ExtractionLimits:
    return ExtractionLimits(
        max_archive_depth=5,
        max_total_extracted_bytes=10 * 1024 * 1024,
        max_single_file_bytes=1024 * 1024,
    )


def _mark_zip_member_encrypted(zip_path: Path, member_name: str) -> None:
    data = bytearray(zip_path.read_bytes())
    encoded_name = member_name.encode("utf-8")
    offset = 0
    while offset < len(data):
        signature = data[offset : offset + 4]
        if signature == b"PK\x03\x04":
            filename_length = struct.unpack_from("<H", data, offset + 26)[0]
            extra_length = struct.unpack_from("<H", data, offset + 28)[0]
            compressed_size = struct.unpack_from("<I", data, offset + 18)[0]
            name_start = offset + 30
            name_end = name_start + filename_length
            if data[name_start:name_end] == encoded_name:
                flag_bits = struct.unpack_from("<H", data, offset + 6)[0] | 0x1
                struct.pack_into("<H", data, offset + 6, flag_bits)
            offset = name_end + extra_length + compressed_size
            continue
        if signature == b"PK\x01\x02":
            filename_length = struct.unpack_from("<H", data, offset + 28)[0]
            extra_length = struct.unpack_from("<H", data, offset + 30)[0]
            comment_length = struct.unpack_from("<H", data, offset + 32)[0]
            name_start = offset + 46
            name_end = name_start + filename_length
            if data[name_start:name_end] == encoded_name:
                flag_bits = struct.unpack_from("<H", data, offset + 8)[0] | 0x1
                struct.pack_into("<H", data, offset + 8, flag_bits)
            offset = name_end + extra_length + comment_length
            continue
        offset += 1
    zip_path.write_bytes(data)


def _read_coverage(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))


def _norm_path(value: str) -> str:
    return value.replace("\\", "/")
