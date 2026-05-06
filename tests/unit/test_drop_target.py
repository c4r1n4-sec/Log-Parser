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


def test_default_output_folder_uses_desktop_case_template(monkeypatch, tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))

    output_dir = drop_target.default_drop_output_dir("60114450", timestamp="20260506-103814")

    assert output_dir == (
        fake_home
        / "Desktop"
        / "TDSYNNEX-CB-LogParser"
        / "Case-60114450-scan-20260506-103814"
    )


def test_detect_case_number_prefers_most_common_path_name(tmp_path: Path) -> None:
    case_dir = tmp_path / "60114450"
    case_dir.mkdir()
    (case_dir / "Broadcom StandardReport_60114450.pdf").write_text("", encoding="utf-8")
    (case_dir / "Case_61234567.zip").write_text("", encoding="utf-8")

    result = drop_target.detect_case_number([str(case_dir)])

    assert result.case_number == "60114450"
    assert result.warnings == []


def test_detect_case_number_warns_when_ambiguous(tmp_path: Path) -> None:
    first = tmp_path / "Case_60114450.zip"
    second = tmp_path / "Case_61234567.zip"
    first.write_text("", encoding="utf-8")
    second.write_text("", encoding="utf-8")

    result = drop_target.detect_case_number([str(first), str(second)])

    assert result.case_number == "60114450"
    assert result.warnings == ["Multiple possible case numbers found; selected 60114450."]


def test_default_output_without_case_uses_unknown(tmp_path: Path, monkeypatch, capsys) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    input_dir = tmp_path / "customer logs"
    input_dir.mkdir()
    (input_dir / "customer.log").write_text("publisher validation failed\n", encoding="utf-8")

    exit_code = drop_target.main([str(input_dir)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Detected case number: UNKNOWN" in captured.out
    output_line = next(
        line for line in captured.out.splitlines() if line.startswith("Output folder: ")
    )
    output_dir = Path(output_line.removeprefix("Output folder: "))
    assert output_dir.parent == fake_home / "Desktop" / "TDSYNNEX-CB-LogParser"
    assert output_dir.name.startswith("Case-UNKNOWN-scan-")
    assert "Scan completed" in captured.out
    assert "Warnings: 0" in captured.out
    assert (output_dir / "triage_report.html").exists()


def test_default_output_config_keys_are_present() -> None:
    defaults = drop_target.load_defaults()

    assert defaults["paths"]["default_output_base"] == "Desktop"
    assert defaults["paths"]["default_output_folder_name"] == "TDSYNNEX-CB-LogParser"
    assert defaults["paths"]["case_folder_template"] == "Case-{case_number}-scan-{timestamp}"


def test_run_scan_writes_partial_reports_on_fatal_pipeline_error(
    tmp_path: Path, monkeypatch
) -> None:
    from app.core.ingest import pipeline as ingest_pipeline

    def fail_process_inputs(self, inputs):  # type: ignore[no-untyped-def]
        raise RuntimeError("synthetic fatal scan failure")

    monkeypatch.setattr(ingest_pipeline.IngestPipeline, "process_inputs", fail_process_inputs)
    output_dir = tmp_path / "partial"

    result = run_scan([str(tmp_path / "input.log")], str(output_dir), ScanOptions())

    assert result.failed
    for report_name in REQUIRED_REPORT_NAMES:
        assert (output_dir / report_name).exists(), report_name
    assert (output_dir / "scan_error.txt").exists()
    assert "synthetic fatal scan failure" in (output_dir / "scan_error.txt").read_text(
        encoding="utf-8"
    )
    assert "Scan failure" in (output_dir / "triage_report.txt").read_text(encoding="utf-8")


def test_streaming_and_partial_report_config_keys_are_present() -> None:
    defaults = drop_target.load_defaults()

    assert defaults["scanning"]["large_file_warning_bytes"] == 268435456
    assert defaults["scanning"]["text_stream_chunk_lines"] == 10000
    assert defaults["scanning"]["binary_chunk_bytes"] == 8388608
    assert defaults["scanning"]["binary_overlap_bytes"] == 4096
    assert defaults["scanning"]["max_context_chars"] == 4000
    assert defaults["reports"]["max_report_examples_per_rule"] == 25
    assert defaults["reports"]["max_report_raw_line_chars"] == 2000
    assert defaults["reports"]["always_write_partial_reports"] is True
