"""Drag-and-drop command-line entry point for customer artifacts."""

from __future__ import annotations

import argparse
import importlib
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

DROP_HELP_MESSAGE = (
    "Drag and drop customer log files, ZIPs, PDFs, or folders onto this EXE or onto "
    "DROP-CUSTOMER-LOGS-HERE.bat."
)
CASE_NUMBER_PATTERN = re.compile(r"(?<!\d)(6\d{7})(?!\d)")
CASE_TEXT_PATTERNS = (
    re.compile(r"\bcase\s+number\s*:?\s*(6\d{7})\b", re.IGNORECASE),
    re.compile(r"\bcase\s*#\s*(6\d{7})\b", re.IGNORECASE),
    re.compile(r"\bcase\s*-\s*(6\d{7})\b", re.IGNORECASE),
    re.compile(r"\bcase\s+(6\d{7})\b", re.IGNORECASE),
)
UNKNOWN_CASE_NUMBER = "UNKNOWN"


@dataclass
class CaseDetectionResult:
    """Detected Broadcom case number details for drop-mode output naming."""

    case_number: str = UNKNOWN_CASE_NUMBER
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
        help="Output folder for reports. Defaults to Desktop case-number timestamp folder.",
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


def default_drop_output_dir(case_number: str) -> Path:
    """Return the default per-run Desktop output folder for dropped artifacts."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder_name = f"Case-{case_number}-scan-{timestamp}"
    return _user_desktop_dir() / "TDSYNNEX-CB-LogParser" / folder_name


def detect_case_number(inputs: list[str]) -> CaseDetectionResult:
    """Detect an 8-digit Broadcom case number from dropped paths and PDF text if available."""
    ordered_matches: list[str] = []
    for input_value in inputs:
        ordered_matches.extend(_case_numbers_from_path(input_value))

    for input_value in inputs:
        ordered_matches.extend(_case_numbers_from_standard_report_pdf_text(Path(input_value)))

    if not ordered_matches:
        return CaseDetectionResult()

    counts = Counter(ordered_matches)
    top_count = max(counts.values())
    most_common = [case_number for case_number, count in counts.items() if count == top_count]
    selected = ordered_matches[0]
    warnings: list[str] = []

    if len(most_common) == 1:
        selected = most_common[0]
    elif len(counts) > 1:
        warnings.append(f"Multiple possible case numbers found; selected {selected}.")

    return CaseDetectionResult(case_number=selected, warnings=warnings)


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
        print(f"Output folder: {output_dir.resolve()}")

        result = run_scan(
            [str(input_path) for input_path in args.inputs],
            str(output_dir),
            ScanOptions(),
        )
        warnings = [*case_detection.warnings, *result.warnings]

        if args.open_output:
            open_warning = _open_output_folder(result.output_dir)
            if open_warning:
                warnings.append(open_warning)

        _print_result(result, warnings)
        return_code = 2 if warnings else 0
        return return_code
    except Exception as exc:
        print(f"Fatal startup error: {exc}", file=sys.stderr)
        return 1
    finally:
        _pause_if_requested(args.pause)


def _user_desktop_dir() -> Path:
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        return Path(user_profile).expanduser() / "Desktop"
    return Path.home() / "Desktop"


def _case_numbers_from_path(input_value: str) -> list[str]:
    path = Path(input_value)
    matches = _case_numbers_from_text(str(path))
    if path.is_dir():
        for child in _iter_case_name_candidates(path):
            matches.extend(_case_numbers_from_text(str(child)))
    return matches


def _iter_case_name_candidates(path: Path) -> list[Path]:
    try:
        return [child for child in path.rglob("*") if child.is_file() or child.is_dir()]
    except OSError:
        return []


def _case_numbers_from_text(text: str) -> list[str]:
    return CASE_NUMBER_PATTERN.findall(text)


def _case_numbers_from_standard_report_pdf_text(path: Path) -> list[str]:
    candidates: list[Path]
    if path.is_file():
        candidates = [path]
    elif path.is_dir():
        try:
            candidates = [child for child in path.rglob("*.pdf") if child.is_file()]
        except OSError:
            candidates = []
    else:
        candidates = []

    matches: list[str] = []
    for candidate in candidates:
        if "standardreport" not in candidate.name.lower():
            continue
        pdf_text = _extract_pdf_text(candidate)
        if pdf_text:
            matches.extend(_case_numbers_from_case_text(pdf_text))
    return matches


def _extract_pdf_text(path: Path) -> str:
    if importlib.util.find_spec("pypdf") is not None:
        pypdf = importlib.import_module("pypdf")
        return _extract_pdf_text_with_reader(pypdf.PdfReader, path)
    if importlib.util.find_spec("PyPDF2") is not None:
        pypdf2 = importlib.import_module("PyPDF2")
        return _extract_pdf_text_with_reader(pypdf2.PdfReader, path)
    return ""


def _extract_pdf_text_with_reader(pdf_reader, path: Path) -> str:
    try:
        reader = pdf_reader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception:
        return ""


def _case_numbers_from_case_text(text: str) -> list[str]:
    matches: list[str] = []
    for pattern in CASE_TEXT_PATTERNS:
        matches.extend(pattern.findall(text))
    return matches


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
    print(f"Report path: {result.report_html_path}")
    print(f"Output folder: {result.output_dir}")
    for warning in warnings:
        print(f"WARNING: {warning}")


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
