"""Drag-and-drop command-line entry point for customer artifacts."""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from app.bootstrap import bootstrap_application
from app.core.jobs.run_scan import ScanOptions, ScanResult, run_scan
from app.core.util.config import load_defaults

DROP_HELP_MESSAGE = (
    "Drag and drop customer log files, ZIPs, PDFs, or folders onto this EXE or onto "
    "DROP-CUSTOMER-LOGS-HERE.bat."
)
CASE_NUMBER_PATTERN = re.compile(r"(?<!\d)(6\d{7})(?!\d)")
STANDARD_REPORT_CASE_PATTERN = re.compile(
    r"\bcase\s*(?:number\s*)?(?:#|:|-)?\s*(6\d{7})(?!\d)", re.IGNORECASE
)


@dataclass(frozen=True)
class CaseDetectionResult:
    """Detected Broadcom case number and any non-fatal selection warnings."""

    case_number: str
    warnings: list[str] = field(default_factory=list)


class DropTargetArgumentParser(argparse.ArgumentParser):
    """Argument parser that shows drag/drop help on parse errors."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(1, f"ERROR: {message}\n{DROP_HELP_MESSAGE}\n")


def build_parser() -> argparse.ArgumentParser:
    """Build the drag/drop CLI parser."""
    parser = DropTargetArgumentParser(
        description="Scan dropped Carbon Black App Control customer artifacts."
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help="Customer log files, ZIPs, PDFs, folders, or other artifacts to scan.",
    )
    parser.add_argument(
        "--output",
        help=(
            "Output folder for reports. Defaults to a case-specific Desktop folder under "
            "TDSYNNEX-CB-LogParser."
        ),
    )
    parser.add_argument(
        "--open-output",
        action="store_true",
        help="Open the output folder after the scan completes.",
    )
    parser.add_argument(
        "--pause",
        action="store_true",
        help="Wait for Enter before closing.",
    )
    return parser


def default_drop_output_dir(case_number: str, timestamp: str | None = None) -> Path:
    """Return the default per-run Desktop output folder for dropped artifacts."""
    config = load_defaults()
    paths = config.get("paths", {})
    base = _configured_output_base(str(paths.get("default_output_base", "Desktop")))
    folder_name = str(paths.get("default_output_folder_name", "TDSYNNEX-CB-LogParser"))
    template = str(paths.get("case_folder_template", "Case-{case_number}-scan-{timestamp}"))
    active_timestamp = timestamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    case_folder = template.format(case_number=case_number or "UNKNOWN", timestamp=active_timestamp)
    return base / folder_name / case_folder


def detect_case_number(inputs: list[str]) -> CaseDetectionResult:
    """Detect an 8-digit Broadcom case number from dropped paths and StandardReport PDFs."""
    detections: list[str] = []
    input_paths = [Path(item).expanduser() for item in inputs]

    for input_path in input_paths:
        detections.extend(_case_numbers_from_path_names(input_path))

    for input_path in input_paths:
        for standard_report_pdf in _standard_report_pdfs(input_path):
            detections.extend(_case_numbers_from_standard_report_pdf(standard_report_pdf))

    if not detections:
        return CaseDetectionResult("UNKNOWN")

    counts = Counter(detections)
    highest_count = max(counts.values())
    top_case_numbers = {case for case, count in counts.items() if count == highest_count}
    selected = next(case for case in detections if case in top_case_numbers)

    warnings: list[str] = []
    if len(top_case_numbers) > 1:
        warnings.append(f"Multiple possible case numbers found; selected {selected}.")
    return CaseDetectionResult(selected, warnings)


def main(argv: list[str] | None = None) -> int:
    """Run the drag/drop CLI entry point."""
    args = build_parser().parse_args(argv)

    if not args.inputs:
        print(DROP_HELP_MESSAGE)
        _pause_if_requested(args.pause)
        return 1

    try:
        bootstrap_application()
        case_detection = detect_case_number([str(input_path) for input_path in args.inputs])
        if args.output:
            output_dir = Path(args.output).expanduser()
        else:
            output_dir = _unique_output_dir(default_drop_output_dir(case_detection.case_number))

        print("Scan started")
        print(f"Inputs received: {len(args.inputs)}")
        print(f"Detected case number: {case_detection.case_number}")
        print(f"Output folder: {output_dir}")

        result = run_scan(
            [str(input_path) for input_path in args.inputs],
            str(output_dir),
            ScanOptions(detected_case_number=case_detection.case_number),
        )
        warnings = [*case_detection.warnings, *result.warnings]

        if args.open_output:
            open_warning = _open_output_folder(result.output_dir)
            if open_warning:
                warnings.append(open_warning)

        _print_result(result, warnings)
        return 0
    except Exception as exc:
        print(f"Fatal startup error: {exc}", file=sys.stderr)
        return 1
    finally:
        _pause_if_requested(args.pause)


def _configured_output_base(configured_base: str) -> Path:
    if configured_base.lower() == "desktop":
        user_profile = os.environ.get("USERPROFILE") if os.name == "nt" else None
        home = Path(user_profile).expanduser() if user_profile else Path.home()
        return home / "Desktop"
    return Path(configured_base).expanduser()


def _case_numbers_from_path_names(path: Path) -> list[str]:
    detections: list[str] = []
    for part in path.parts:
        detections.extend(CASE_NUMBER_PATTERN.findall(part))
    if path.is_dir():
        for child in path.rglob("*"):
            for part in child.relative_to(path).parts:
                detections.extend(CASE_NUMBER_PATTERN.findall(part))
    return detections


def _standard_report_pdfs(path: Path) -> list[Path]:
    candidates: list[Path] = []
    if path.is_file():
        candidates = [path]
    elif path.is_dir():
        candidates = [candidate for candidate in path.rglob("*.pdf") if candidate.is_file()]
    return [candidate for candidate in candidates if _is_standard_report_pdf(candidate)]


def _is_standard_report_pdf(path: Path) -> bool:
    lower_name = path.name.lower()
    return path.suffix.lower() == ".pdf" and "standard" in lower_name and "report" in lower_name


def _case_numbers_from_standard_report_pdf(path: Path) -> list[str]:
    text = _extract_pdf_text_if_available(path)
    if not text:
        return []
    return STANDARD_REPORT_CASE_PATTERN.findall(text)


def _extract_pdf_text_if_available(path: Path) -> str:
    if importlib.util.find_spec("pypdf") is not None:
        from pypdf import PdfReader  # type: ignore[import-not-found]

        return _extract_pdf_text_with_reader(PdfReader, path)
    if importlib.util.find_spec("PyPDF2") is not None:
        from PyPDF2 import PdfReader  # type: ignore[import-not-found]

        return _extract_pdf_text_with_reader(PdfReader, path)
    return ""


def _extract_pdf_text_with_reader(pdf_reader: object, path: Path) -> str:
    try:
        reader = pdf_reader(str(path))  # type: ignore[operator]
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception:
        return ""


def _unique_output_dir(output_dir: Path) -> Path:
    """Avoid overwriting an existing default timestamp folder."""
    candidate = output_dir
    suffix = 1
    while candidate.exists() and any(candidate.iterdir()):
        candidate = output_dir.with_name(f"{output_dir.name}-{suffix}")
        suffix += 1
    return candidate


def _print_result(result: ScanResult, warnings: list[str]) -> None:
    print("Scan completed")
    print(f"Files discovered: {result.artifact_count}")
    print(f"Files scanned: {result.scanned_count}")
    print(f"Findings count: {result.hit_count}")
    print(f"Warnings: {len(warnings)}")
    for warning in warnings:
        print(f"WARNING: {warning}")
    print(f"Report path: {result.report_html_path}")
    print(f"Output folder: {result.output_dir}")


def _open_output_folder(output_dir: Path) -> str:
    try:
        if hasattr(os, "startfile"):
            os.startfile(output_dir)  # type: ignore[attr-defined]
            return ""
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.Popen([opener, str(output_dir)])
        return ""
    except OSError as exc:
        return f"Could not open output folder: {exc}"


def _pause_if_requested(should_pause: bool) -> None:
    if not should_pause:
        return
    try:
        input("Press Enter to close...")
    except EOFError:
        return


if __name__ == "__main__":
    raise SystemExit(main())
