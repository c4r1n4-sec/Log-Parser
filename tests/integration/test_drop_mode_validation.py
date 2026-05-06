"""Validation tests for the drag/drop source CLI workflow."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
import zipfile
from pathlib import Path

from app.core.jobs.run_scan import REQUIRED_REPORT_NAMES

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_RULE_IDS = {
    "APPC_SQL_TIMEOUT",
    "APPC_CERT_CN_MISMATCH",
    "APPC_DISC_AGENT_41002",
    "APPC_SQL_ROLE_DSN_APPCWEBSERVER",
}


def test_drop_mode_source_cli_custom_output_validates_reports_and_hits(tmp_path: Path) -> None:
    output_dir = tmp_path / "custom drop output"
    fixture_dir = _make_drop_mode_fixture(tmp_path)
    completed = _run_drop_target([str(fixture_dir), "--output", str(output_dir)])

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Scan started" in completed.stdout
    assert "Inputs received: 1" in completed.stdout
    assert f"Output folder: {output_dir}" in completed.stdout
    _assert_required_reports(output_dir)
    _assert_expected_evidence(output_dir)


def test_drop_mode_source_cli_default_desktop_case_output(tmp_path: Path) -> None:
    fake_home = tmp_path / "home with spaces"
    fake_home.mkdir()

    case_dir = tmp_path / "60114450"
    case_dir.mkdir()
    _make_drop_mode_fixture(case_dir)

    completed = _run_drop_target([str(case_dir)], home=fake_home)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    output_line = next(
        line for line in completed.stdout.splitlines() if line.startswith("Output folder: ")
    )
    output_dir = Path(output_line.removeprefix("Output folder: "))
    expected_parent = fake_home / "Desktop" / "TDSYNNEX-CB-LogParser"
    assert output_dir.parent == expected_parent
    assert output_dir.name.startswith("Case-60114450-scan-")
    assert "Detected case number: 60114450" in completed.stdout
    _assert_required_reports(output_dir)


def test_drop_mode_source_cli_pause_does_not_break_scan(tmp_path: Path) -> None:
    output_dir = tmp_path / "pause output"

    completed = _run_drop_target(
        [str(_make_drop_mode_fixture(tmp_path)), "--output", str(output_dir), "--pause"],
        input_text="\n",
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Press Enter to close" in completed.stdout
    _assert_required_reports(output_dir)



def _make_drop_mode_fixture(base_dir: Path) -> Path:
    fixture_dir = base_dir / "drop_mode_case"
    fixture_dir.mkdir(exist_ok=True)
    (fixture_dir / "ReporterLog-test.txt").write_text(
        "ReporterService\nExecution Timeout Expired\nAntibodyMetadataLookup\n",
        encoding="utf-8",
    )
    (fixture_dir / "ServerLog.bt9").write_text(
        "ServerLog Carbon Black App Control\nAppCWebServer add_server_role failed\n",
        encoding="utf-8",
    )
    (fixture_dir / "trace.bt9").write_text(
        "trace.bt9\nServer Communication\nGetSslError[16]\nConnection: Connected(Waiting)\n",
        encoding="utf-8",
    )
    (fixture_dir / "binary-test.bin").write_bytes(
        b"BINARY\0ReporterConnectivityError services.bit9.com timeout\0"
    )
    nested_log = base_dir / "nested-reviewed.log"
    nested_log.write_text("AppCWebServer add_server_role failed\n", encoding="utf-8")
    with zipfile.ZipFile(fixture_dir / "nested-logs.zip", "w") as archive:
        archive.write(nested_log, "nested/nested-reviewed.log")
    return fixture_dir

def _run_drop_target(
    args: list[str], home: Path | None = None, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    if home is not None:
        env["HOME"] = str(home)
    return subprocess.run(
        [sys.executable, "-m", "app.drop_target", *args],
        cwd=REPO_ROOT,
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def _assert_required_reports(output_dir: Path) -> None:
    for report_name in REQUIRED_REPORT_NAMES:
        assert (output_dir / report_name).exists(), report_name


def _assert_expected_evidence(output_dir: Path) -> None:
    hits = _read_csv(output_dir / "all_hits.csv")
    coverage = _read_csv(output_dir / "artifact_coverage.csv")
    hit_rule_ids = {hit["rule_id"] for hit in hits}

    assert EXPECTED_RULE_IDS <= hit_rule_ids
    assert all(hit["rule_id"] != "GENERIC_SEARCH" for hit in hits)
    assert not (output_dir / "generic_hits.csv").exists()
    assert any(row["artifact_path"].endswith("nested-reviewed.log") for row in coverage)
    assert all(
        not hit["kb_candidate_ids"] or "KB candidate" in hit["kb_candidate_ids"]
        for hit in hits
    )

    report_names = (
        "triage_report.txt",
        "triage_report.html",
        "missing_evidence_checklist.txt",
    )
    for report_name in report_names:
        report_text = (output_dir / report_name).read_text(encoding="utf-8")
        assert "confirmed root cause" not in report_text.lower()
    assert "KB candidate" in (output_dir / "triage_report.txt").read_text(encoding="utf-8")


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))


def test_large_streaming_chunked_and_limited_artifacts_use_desktop_case_output(
    tmp_path: Path, monkeypatch
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    case_dir = tmp_path / "60114450"
    case_dir.mkdir()

    large_log = case_dir / "large.log"
    with large_log.open("w", encoding="utf-8") as file_obj:
        for index in range(35):
            file_obj.write(f"{index} Execution Timeout Expired AntibodyMetadataLookup\n")
        file_obj.write("x" * (1024 * 1024 + 8))

    huge_csv = case_dir / "huge.csv"
    with huge_csv.open("w", encoding="utf-8") as file_obj:
        file_obj.write("line,message\n")
        file_obj.write("1,ReporterConnectivityError services.bit9.com\n")
        file_obj.write("x" * (600 * 1024) + "\n")
        file_obj.write("2,GetSslError[16]\n")
        file_obj.write("y" * (600 * 1024) + "\n")
        file_obj.write("3,Timeout expired\n")

    binary_path = case_dir / "chunk-boundary.bin"
    boundary_fill = 8 * 1024 * 1024 - len(b"Execution ") - len(b"BINARY\0")
    boundary_prefix = b"BINARY\0" + (b"\0" * boundary_fill)
    binary_path.write_bytes(boundary_prefix + b"Execution Timeout Expired" + b"\0tail")

    (case_dir / "Trace.bt9").write_bytes(b"")
    (case_dir / "capture.etl").write_bytes(b"ETL Execution Timeout Expired")
    pml_path = case_dir / "capture.pml"
    pml_path.write_bytes(b"PML" + (b"\0" * (1024 * 1024 + 1)) + b"services.bit9.com")
    dmp_path = tmp_path / "memory.dmp"
    dmp_path.write_bytes(b"DMP ReporterConnectivityError services.bit9.com")
    with zipfile.ZipFile(case_dir / "nested.dmp.zip", "w") as archive:
        archive.write(dmp_path, "nested/memory.dmp")

    exit_code = __import__("app.drop_target", fromlist=["drop_target"]).main([str(case_dir)])

    assert exit_code == 0
    output_base = fake_home / "Desktop" / "TDSYNNEX-CB-LogParser"
    output_dirs = list(output_base.glob("Case-60114450-scan-*"))
    assert len(output_dirs) == 1
    output_dir = output_dirs[0]
    for report_name in REQUIRED_REPORT_NAMES:
        assert (output_dir / report_name).exists(), report_name

    coverage = _read_csv(output_dir / "artifact_coverage.csv")
    rows_by_name = {Path(row["artifact_path"]).name: row for row in coverage}
    for expected in (
        "large.log",
        "huge.csv",
        "chunk-boundary.bin",
        "Trace.bt9",
        "capture.etl",
        "capture.pml",
        "nested.dmp.zip",
        "memory.dmp",
    ):
        assert expected in rows_by_name
    assert all("File exceeds max_single_file_bytes" not in row["limitations"] for row in coverage)
    assert rows_by_name["large.log"]["review_mode"] == "stream-scanned"
    assert rows_by_name["huge.csv"]["review_mode"] == "stream-scanned"
    assert rows_by_name["chunk-boundary.bin"]["review_mode"] == "binary-string-scanned"
    assert rows_by_name["capture.pml"]["artifact_family"] == "procmon_pml"
    assert rows_by_name["capture.pml"]["review_mode"] == "binary-string-scanned"
    assert "ProcMon PML binary was not fully decoded" in rows_by_name["capture.pml"]["limitations"]
    assert rows_by_name["memory.dmp"]["artifact_family"] == "memory_dump"
    assert "Memory dump was not debugger-decoded" in rows_by_name["memory.dmp"]["limitations"]

    hits = _read_csv(output_dir / "all_hits.csv")
    assert any(hit["artifact_path"].endswith("large.log") for hit in hits)
    assert any(hit["artifact_path"].endswith("huge.csv") for hit in hits)
    assert any(hit["artifact_path"].endswith("chunk-boundary.bin") for hit in hits)
    checklist_text = (output_dir / "missing_evidence_checklist.txt").read_text(encoding="utf-8")
    assert "trace.bt9 present but empty" in checklist_text
    html = (output_dir / "triage_report.html").read_text(encoding="utf-8")
    assert html.count("rule_id:</strong> APPC_SQL_TIMEOUT") <= 25
