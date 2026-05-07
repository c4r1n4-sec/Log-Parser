"""Static checks for the Windows drag/drop BAT handoff files."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_root_drop_bat_contains_required_drag_drop_behavior() -> None:
    bat_path = REPO_ROOT / "DROP-CUSTOMER-LOGS-HERE.bat"
    bat_text = bat_path.read_text(encoding="utf-8")

    assert bat_path.exists()
    assert 'set "BAT_DIR=%~dp0"' in bat_text
    assert 'set "EXE=%BAT_DIR%TDSYNNEX-CB-LogParser.exe"' in bat_text
    assert 'set "EXE=%BAT_DIR%dist\\TDSYNNEX-CB-LogParser\\TDSYNNEX-CB-LogParser.exe"' in bat_text
    assert (
        "TDSYNNEX-CB-LogParser.exe was not found. This BAT must be in the same folder "
        "as the portable EXE."
    ) in bat_text
    assert (
        "Drag and drop customer logs, ZIPs, PDFs, folders, or screenshots onto this BAT file."
        in bat_text
    )
    assert "pause" in bat_text.lower()
    assert '"%EXE%" --open-output --pause %*' in bat_text
    assert "%*" in bat_text
    assert "TDSYNNEX Carbon Black Log Parser" in bat_text
    assert "Drag/drop mode" in bat_text
    assert "Reports will be written to your Desktop under TDSYNNEX-CB-LogParser." in bat_text


def test_drop_mode_readme_documents_manual_bat_validation() -> None:
    readme_path = REPO_ROOT / "README-DROP-MODE.txt"
    readme_text = readme_path.read_text(encoding="utf-8")

    assert readme_path.exists()
    assert "Unzip the portable package" in readme_text
    assert "Drag customer files or folders onto DROP-CUSTOMER-LOGS-HERE.bat" in readme_text
    assert (
        "%USERPROFILE%\\Desktop\\TDSYNNEX-CB-LogParser\\Case-60114450-scan-YYYYMMDD-HHMMSS"
        in readme_text
    )
    assert "Documents\\TDSYNNEX-CB-LogParser" not in readme_text
    assert "bundled output folder" not in readme_text
    assert "open triage_report.html" in readme_text.lower()
    assert "local-only" in readme_text
    assert "No logs are uploaded" in readme_text
    assert "KBs are candidates only" in readme_text
    assert "does not prove root cause automatically" in readme_text
    assert "Manual BAT test steps" in readme_text
    assert "path contains spaces" in readme_text
    assert "multiple files/folders" in readme_text


def test_script_portable_bat_uses_python_drop_target_without_exe() -> None:
    bat_path = REPO_ROOT / "RUN-CB-LOG-PARSER.bat"
    bat_text = bat_path.read_text(encoding="utf-8")

    assert bat_path.exists()
    assert "TDSYNNEX Carbon Black Log Parser" in bat_text
    assert "Script portable mode" in bat_text
    assert "Reports will be written to your Desktop under TDSYNNEX-CB-LogParser." in bat_text
    assert "py -3.11" in bat_text
    assert "py -3" in bat_text
    assert "python" in bat_text
    assert '.venv\\Scripts\\python.exe" -m app.drop_target' in bat_text
    assert "--open-output" in bat_text
    assert "--pause" in bat_text
    assert "%*" in bat_text
    assert "requirements-cli.txt" in bat_text
    assert "TDSYNNEX-CB-LogParser.exe" not in bat_text


def test_script_portable_requirements_exclude_gui_dependency() -> None:
    requirements_path = REPO_ROOT / "requirements-cli.txt"
    requirements_text = requirements_path.read_text(encoding="utf-8")

    assert requirements_path.exists()
    assert "Jinja2>=3.1,<4" in requirements_text
    assert "PySide6" not in requirements_text


def test_aws_windows_vm_usage_doc_exists_and_describes_script_mode() -> None:
    doc_path = REPO_ROOT / "docs" / "aws_windows_vm_usage.md"
    doc_text = doc_path.read_text(encoding="utf-8")

    assert doc_path.exists()
    assert "AWS Windows 11 diagnostic VMs" in doc_text
    assert "unsigned PyInstaller EXE is blocked" in doc_text
    assert "Python 3.11 should be installed in the VM image" in doc_text
    assert "Keep Defender enabled" in doc_text
    assert "Smart App Control may block unsigned EXEs and has no per-app allowlist" in doc_text
    assert "Drag case ZIPs/folders onto `RUN-CB-LOG-PARSER.bat`" in doc_text
    assert "Desktop\\TDSYNNEX-CB-LogParser\\Case-<case>-scan-<timestamp>" in doc_text
