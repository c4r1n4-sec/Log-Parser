"""Tests for drag/drop command-line scanning."""

from __future__ import annotations

import builtins
import csv
from pathlib import Path

from app import drop_target
from app.core.jobs.run_scan import REQUIRED_REPORT_NAMES, ScanOptions, run_scan
from app.core.util.config import ExtractionLimits


def test_no_args_prints_drag_drop_message(capsys) -> None:
    exit_code = drop_target.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert drop_target.DROP_HELP_MESSAGE in captured.out


def test_pause_waits_for_enter_when_no_inputs(monkeypatch, capsys) -> None:
    paused = False

    def fake_input(prompt: str) -> str:
        nonlocal paused
        paused = True
        assert "Press Enter" in prompt
        return ""

    monkeypatch.setattr(builtins, "input", fake_input)

    exit_code = drop_target.main(["--pause"])

    assert exit_code == 1
    assert paused
    assert drop_target.DROP_HELP_MESSAGE in capsys.readouterr().out


def test_single_input_folder_creates_required_reports(tmp_path: Path, capsys) -> None:
    input_dir = tmp_path / "case"
    input_dir.mkdir()
    (input_dir / "trace.bt9").write_text("Connected(Waiting) GetSslError\n", encoding="utf-8")
    output_dir = tmp_path / "reports"

    exit_code = drop_target.main([str(input_dir), "--output", str(output_dir)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Scan started" in captured.out
    assert "Inputs received: 1" in captured.out
    assert "Files discovered: 1" in captured.out
    assert "Files scanned: 1" in captured.out
    assert "Findings count:" in captured.out
    _assert_required_reports(output_dir)
    assert "Confirmed root cause" not in (output_dir / "triage_report.txt").read_text(
        encoding="utf-8"
    )


def test_multiple_input_paths_scan_all_inputs(tmp_path: Path, capsys) -> None:
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    first.write_text("error connecting to proxy\n", encoding="utf-8")
    second.write_text("services.bit9.com timeout\n", encoding="utf-8")
    output_dir = tmp_path / "multi-output"

    exit_code = drop_target.main([str(first), str(second), "--output", str(output_dir)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Inputs received: 2" in captured.out
    assert "Files discovered: 2" in captured.out
    assert len(_read_csv(output_dir / "artifact_coverage.csv")) == 2
    _assert_required_reports(output_dir)


def test_default_output_folder_uses_desktop_case_folder(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    user_profile = tmp_path / "User Profile"
    user_profile.mkdir()
    monkeypatch.setenv("USERPROFILE", str(user_profile))
    input_dir = tmp_path / "60114450"
    input_dir.mkdir()
    (input_dir / "trace.bt9").write_text(
        "Connected(Waiting) GetSslError\n", encoding="utf-8"
    )

    exit_code = drop_target.main([str(input_dir)])

    captured = capsys.readouterr()
    expected_base = user_profile / "Desktop" / "TDSYNNEX-CB-LogParser"
    case_dirs = list(expected_base.glob("Case-60114450-scan-*"))
    assert exit_code == 0
    assert len(case_dirs) == 1
    assert (case_dirs[0] / "triage_report.html").exists()
    assert "Detected case number: 60114450" in captured.out
    assert f"Output folder: {case_dirs[0].resolve()}" in captured.out
    assert "Scan completed" in captured.out
    assert "Warnings: 0" in captured.out


def test_folder_named_case_number_is_detected(tmp_path: Path) -> None:
    input_dir = tmp_path / "60114450"
    input_dir.mkdir()

    result = drop_target.detect_case_number([str(input_dir)])

    assert result.case_number == "60114450"
    assert result.warnings == []


def test_standardreport_pdf_filename_detects_case_number(tmp_path: Path) -> None:
    pdf_path = tmp_path / "Broadcom StandardReport_60114450.pdf"
    pdf_path.write_bytes(b"not a real pdf")

    result = drop_target.detect_case_number([str(pdf_path)])

    assert result.case_number == "60114450"
    assert result.warnings == []


def test_ambiguous_case_numbers_create_warning(tmp_path: Path) -> None:
    first = tmp_path / "Case_60114450.zip"
    second = tmp_path / "StandardReport-60114451.pdf"
    first.write_text("one", encoding="utf-8")
    second.write_text("two", encoding="utf-8")

    result = drop_target.detect_case_number([str(first), str(second)])

    assert result.case_number == "60114450"
    assert result.warnings == [
        "Multiple possible case numbers found; selected 60114450."
    ]


def test_custom_output_folder_is_used(tmp_path: Path, monkeypatch, capsys) -> None:
    input_dir = tmp_path / "case"
    input_dir.mkdir()
    (input_dir / "customer.log").write_text("publisher validation failed\n", encoding="utf-8")
    custom_output = tmp_path / "custom" / "drop-results"
    user_profile = tmp_path / "User Profile"
    user_profile.mkdir()
    monkeypatch.setenv("USERPROFILE", str(user_profile))

    exit_code = drop_target.main([str(input_dir), "--output", str(custom_output)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert (custom_output / "triage_report.html").exists()
    assert (custom_output / "triage_report.txt").exists()
    assert not (custom_output / "scans").exists()
    assert not (user_profile / "Desktop" / "TDSYNNEX-CB-LogParser").exists()
    assert f"Output folder: {custom_output.resolve()}" in captured.out


def test_run_scan_result_fields(tmp_path: Path) -> None:
    log_path = tmp_path / "ReporterLog.txt"
    log_path.write_text("ReporterConnectivityError services.bit9.com\n", encoding="utf-8")
    output_dir = tmp_path / "shared-result"

    result = run_scan(
        [str(log_path)],
        str(output_dir),
        ScanOptions(limits=_test_limits()),
    )

    assert result.output_dir == output_dir.resolve()
    assert result.artifact_count == 1
    assert result.scanned_count == 1
    assert result.hit_count >= 1
    assert result.critical_count >= 0
    assert result.high_count >= 0
    assert result.medium_count >= 0
    assert result.low_count >= 0
    assert result.info_count >= 0
    assert isinstance(result.warnings, list)
    assert result.report_html_path == output_dir.resolve() / "triage_report.html"
    assert result.report_txt_path == output_dir.resolve() / "triage_report.txt"
    assert result.report_html_path.exists()
    assert result.report_txt_path.exists()
    _assert_required_reports(output_dir)


def _test_limits() -> ExtractionLimits:
    return ExtractionLimits(
        max_archive_depth=5,
        max_total_extracted_bytes=10 * 1024 * 1024,
        max_single_file_bytes=1024 * 1024,
    )


def _assert_required_reports(output_dir: Path) -> None:
    for report_name in REQUIRED_REPORT_NAMES:
        assert (output_dir / report_name).exists(), report_name


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))
