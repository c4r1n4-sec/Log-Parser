"""Drag-and-drop command-line entry point for customer artifacts."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from app.bootstrap import bootstrap_application
from app.core.jobs.run_scan import ScanOptions, ScanResult, run_scan

DROP_HELP_MESSAGE = (
    "Drag and drop customer log files, ZIPs, PDFs, or folders onto this EXE or onto "
    "DROP-CUSTOMER-LOGS-HERE.bat."
)


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
        help="Output folder for reports. Defaults to Documents scan timestamp folder.",
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


def default_drop_output_dir() -> Path:
    """Return the default per-run Documents output folder for dropped artifacts."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path.home() / "Documents" / "TDSYNNEX-CB-LogParser" / f"scan-{timestamp}"


def main(argv: list[str] | None = None) -> int:
    """Run the drag/drop CLI entry point."""
    args = build_parser().parse_args(argv)

    if not args.inputs:
        print(DROP_HELP_MESSAGE)
        _pause_if_requested(args.pause)
        return 1

    try:
        bootstrap_application()
        if args.output:
            output_dir = Path(args.output).expanduser()
        else:
            output_dir = _unique_output_dir(default_drop_output_dir())

        print("Scan started")
        print(f"Inputs received: {len(args.inputs)}")
        print(f"Output folder: {output_dir}")

        result = run_scan(
            [str(input_path) for input_path in args.inputs],
            str(output_dir),
            ScanOptions(),
        )
        warnings = list(result.warnings)

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


def _unique_output_dir(output_dir: Path) -> Path:
    """Avoid overwriting an existing default timestamp folder."""
    candidate = output_dir
    suffix = 1
    while candidate.exists() and any(candidate.iterdir()):
        candidate = output_dir.with_name(f"{output_dir.name}-{suffix}")
        suffix += 1
    return candidate


def _print_result(result: ScanResult, warnings: list[str]) -> None:
    print(f"Files discovered: {result.artifact_count}")
    print(f"Files scanned: {result.scanned_count}")
    print(f"Findings count: {result.hit_count}")
    print(f"Report path: {result.report_html_path}")
    if warnings:
        print(f"Warnings: {len(warnings)}")
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
