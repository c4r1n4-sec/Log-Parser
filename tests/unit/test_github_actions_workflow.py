"""Static checks for the Windows portable build GitHub Actions workflow."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "build-windows-portable.yml"


def test_windows_portable_workflow_builds_and_uploads_zip() -> None:
    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert WORKFLOW_PATH.exists()
    assert "workflow_dispatch:" in workflow_text
    assert "push:" in workflow_text
    assert "main" in workflow_text
    assert "runs-on: windows-latest" in workflow_text
    assert "actions/checkout@" in workflow_text
    assert "actions/setup-python@" in workflow_text
    assert 'python-version: "3.11"' in workflow_text
    assert "python -m pip install -r requirements.txt" in workflow_text
    assert "python -m pip install pyinstaller pytest" in workflow_text
    assert "python -m pytest -q" in workflow_text
    assert "powershell -ExecutionPolicy Bypass -File .\\build-portable.ps1" in workflow_text
    assert "actions/upload-artifact@" in workflow_text
    assert "name: TDSYNNEX-CB-LogParser-portable" in workflow_text
    assert "dist/TDSYNNEX-CB-LogParser-portable.zip" in workflow_text
    assert "setup.exe" not in workflow_text.lower()
    assert "msi" not in workflow_text.lower()
