"""Static checks for portable ZIP download documentation."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_download_doc_points_to_actions_artifact_not_source_zip() -> None:
    doc_path = REPO_ROOT / "docs" / "download_portable_zip.md"
    text = doc_path.read_text(encoding="utf-8")

    assert doc_path.exists()
    assert "Do **not** use GitHub's **Code > Download ZIP**" in text
    assert "Actions > Build Windows Portable Drag/Drop ZIP" in text
    assert "Artifacts > TDSYNNEX-CB-LogParser-portable" in text
    assert "dist/TDSYNNEX-CB-LogParser-portable.zip" in text
    assert "TDSYNNEX-CB-LogParser.exe" in text
    assert "DROP-CUSTOMER-LOGS-HERE.bat" in text
    assert "does not require Python" in text
    assert "does not require administrator rights" in text
    assert "does not create" in text
    assert "setup.exe" in text


def test_readme_warns_source_zip_is_not_the_portable_tool() -> None:
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Code > Download ZIP" in readme_text
    assert "source code only" in readme_text
    assert "docs/download_portable_zip.md" in readme_text
