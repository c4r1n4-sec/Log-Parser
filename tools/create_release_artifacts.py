"""Create handoff ZIPs and a test summary for release review.

The script packages the repository source tree and, when present, the
PyInstaller ``dist/TDSYNNEX-CB-LogParser`` portable folder. It intentionally
runs from the repository root and excludes transient files so the source ZIP is
small, repeatable, and free of virtual environments or Git internals.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

REPO_ZIP_NAME = "TDSYNNEX-CB-LogParser-repository.zip"
DIST_ZIP_NAME = "TDSYNNEX-CB-LogParser-dist.zip"
DIST_DIR = Path("dist") / "TDSYNNEX-CB-LogParser"
DEFAULT_ARTIFACT_DIR = Path("release_artifacts")

EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "release_artifacts",
    "venv",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create repository/dist ZIP artifacts and a pytest summary."
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR,
        help="Directory for generated ZIPs and test_output_summary.txt.",
    )
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=DIST_DIR,
        help="Portable PyInstaller folder to ZIP after it has been built.",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Do not run pytest; only create ZIP artifacts.",
    )
    parser.add_argument(
        "--allow-missing-dist",
        action="store_true",
        help="Create the repository ZIP and summary even when the dist folder is absent.",
    )
    return parser.parse_args()


def should_include(path: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return False
    if path.suffix in EXCLUDED_SUFFIXES:
        return False
    return True


def iter_repo_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and should_include(path.relative_to(root))
    )


def write_zip(zip_path: Path, files: list[tuple[Path, Path]]) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source, archive_name in files:
            archive.write(source, archive_name.as_posix())


def create_repo_zip(root: Path, artifact_dir: Path) -> Path:
    zip_path = artifact_dir / REPO_ZIP_NAME
    files = [(path, path.relative_to(root)) for path in iter_repo_files(root)]
    write_zip(zip_path, files)
    return zip_path


def create_dist_zip(root: Path, dist_dir: Path, artifact_dir: Path) -> Path:
    dist_path = dist_dir if dist_dir.is_absolute() else root / dist_dir
    files = [
        (path, path.relative_to(dist_path.parent))
        for path in sorted(dist_path.rglob("*"))
        if path.is_file() and path.suffix not in EXCLUDED_SUFFIXES
    ]
    zip_path = artifact_dir / DIST_ZIP_NAME
    write_zip(zip_path, files)
    return zip_path


def run_pytest(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def write_summary(
    artifact_dir: Path,
    repo_zip: Path,
    dist_zip: Path | None,
    pytest_result: subprocess.CompletedProcess[str] | None,
    dist_missing: bool,
) -> Path:
    summary_path = artifact_dir / "test_output_summary.txt"
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "TDSYNNEX Carbon Black Log Parser release artifact summary",
        f"Generated: {timestamp}",
        "",
        f"Repository ZIP: {repo_zip}",
        f"dist portable ZIP: {dist_zip if dist_zip else 'not created'}",
    ]
    if dist_missing:
        lines.append("dist portable ZIP note: dist/TDSYNNEX-CB-LogParser was not present.")
    lines.append("")

    if pytest_result is None:
        lines.append("Tests: skipped by --skip-tests")
    else:
        lines.extend(
            [
                f"Test command: {sys.executable} -m pytest -q",
                f"Exit code: {pytest_result.returncode}",
                "Output:",
                pytest_result.stdout.rstrip(),
            ]
        )
    summary_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return summary_path


def main() -> int:
    args = parse_args()
    root = Path.cwd()
    artifact_dir = (
        args.artifact_dir if args.artifact_dir.is_absolute() else root / args.artifact_dir
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)

    repo_zip = create_repo_zip(root, artifact_dir)

    dist_path = args.dist_dir if args.dist_dir.is_absolute() else root / args.dist_dir
    dist_missing = not dist_path.is_dir()
    dist_zip: Path | None = None
    if dist_missing:
        if not args.allow_missing_dist:
            print(
                f"ERROR: {dist_path} does not exist. Build the portable folder first or pass "
                "--allow-missing-dist.",
                file=sys.stderr,
            )
            return 2
    else:
        dist_zip = create_dist_zip(root, args.dist_dir, artifact_dir)

    pytest_result = None if args.skip_tests else run_pytest(root)
    summary_path = write_summary(artifact_dir, repo_zip, dist_zip, pytest_result, dist_missing)

    print(f"Repository ZIP: {repo_zip}")
    print(f"dist portable ZIP: {dist_zip if dist_zip else 'not created'}")
    print(f"Test output summary: {summary_path}")
    if pytest_result is not None and pytest_result.returncode != 0:
        return pytest_result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
