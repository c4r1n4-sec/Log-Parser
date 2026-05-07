"""Static checks for portable PyInstaller drop-target packaging."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_drop_target_spec_builds_console_one_folder_drop_exe() -> None:
    spec_path = REPO_ROOT / "packaging" / "pyinstaller" / "drop_target.spec"
    spec_text = spec_path.read_text(encoding="utf-8")

    assert spec_path.exists()
    assert '"app" / "drop_target.py"' in spec_text
    assert 'name="TDSYNNEX-CB-LogParser"' in spec_text
    assert "console=True" in spec_text
    assert 'name="TDSYNNEX-CB-LogParser"' in spec_text
    assert '"rules"' in spec_text
    assert '"templates"' in spec_text
    assert '"app" / "config" / "defaults.json"' in spec_text
    assert '"tools"' in spec_text
    assert '"DROP-CUSTOMER-LOGS-HERE.bat"' in spec_text
    assert '"README-DROP-MODE.txt"' in spec_text
    assert "installer" in spec_text.lower()
    assert "does not create" in spec_text.lower()


def test_build_portable_script_runs_tests_builds_zip_and_copies_handoff_files() -> None:
    script_path = REPO_ROOT / "build-portable.ps1"
    script_text = script_path.read_text(encoding="utf-8")

    assert script_path.exists()
    assert "python -m venv" in script_text
    assert "requirements.txt" in script_text
    assert "pip install pyinstaller" in script_text
    assert "pytest -q" in script_text
    assert "packaging\\pyinstaller\\drop_target.spec" in script_text
    assert "TDSYNNEX-CB-LogParser.exe" in script_text
    assert "DROP-CUSTOMER-LOGS-HERE.bat" in script_text
    assert "README-DROP-MODE.txt" in script_text
    assert "Compress-Archive" in script_text
    assert "TDSYNNEX-CB-LogParser-portable.zip" in script_text
    assert "setup.exe" not in script_text.lower()
    assert "msi" not in script_text.lower()


def test_build_portable_bat_invokes_powershell_script() -> None:
    script_path = REPO_ROOT / "build-portable.bat"
    script_text = script_path.read_text(encoding="utf-8")

    assert script_path.exists()
    assert "powershell.exe" in script_text
    assert "build-portable.ps1" in script_text
    assert "%*" in script_text


def test_portable_docs_describe_desktop_case_number_default_output() -> None:
    doc_paths = [
        REPO_ROOT / "docs" / "portable_usage.md",
        REPO_ROOT / "packaging" / "portable" / "README.txt",
    ]

    for doc_path in doc_paths:
        doc_text = doc_path.read_text(encoding="utf-8")
        assert "Desktop" in doc_text
        assert "TDSYNNEX-CB-LogParser" in doc_text
        assert "Case-60114450-scan-YYYYMMDD-HHMMSS" in doc_text
        assert "Documents\\TDSYNNEX-CB-LogParser" not in doc_text
        assert "bundled output folder" not in doc_text
        assert "portable folder output as default" not in doc_text


def test_workflow_uploads_script_portable_runner_artifact() -> None:
    workflow_path = REPO_ROOT / ".github" / "workflows" / "build-windows-portable.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")

    assert workflow_path.exists()
    assert "Stage script portable runner" in workflow_text
    assert "RUN-CB-LOG-PARSER.bat" in workflow_text
    assert "requirements-cli.txt" in workflow_text
    assert "TDSYNNEX-CB-LogParser-script-portable" in workflow_text


def test_aws_windows_vm_usage_documents_script_portable_runner() -> None:
    doc_path = REPO_ROOT / "docs" / "aws_windows_vm_usage.md"
    doc_text = doc_path.read_text(encoding="utf-8")

    assert doc_path.exists()
    assert "AWS Windows VM script-portable usage" in doc_text
    assert "py -3.11" in doc_text
    assert "py -3" in doc_text
    assert "python" in doc_text
    assert "RUN-CB-LOG-PARSER.bat" in doc_text
    assert ".venv\\Scripts\\python.exe -m app.drop_target --open-output --pause %*" in doc_text
    assert "TDSYNNEX-CB-LogParser-script-portable" in doc_text
    assert "PySide6" in doc_text
