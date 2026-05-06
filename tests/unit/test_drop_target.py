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


def test_custom_output_folder_is_used(tmp_path: Path) -> None:
    input_dir = tmp_path / "case"
    input_dir.mkdir()
    (input_dir / "customer.log").write_text("publisher validation failed\n", encoding="utf-8")
    custom_output = tmp_path / "custom" / "drop-results"

    exit_code = drop_target.main([str(input_dir), "--output", str(custom_output)])

    assert exit_code == 0
    assert (custom_output / "triage_report.html").exists()
    assert (custom_output / "triage_report.txt").exists()
    assert not (custom_output / "scans").exists()


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
