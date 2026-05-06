"""Logging helpers for future scan execution."""

from __future__ import annotations

import logging
from pathlib import Path

LOG_FILE_NAME = "tdsynnex_carbon_black_log_parser.log"


def configure_scan_logging(output_dir: Path) -> Path:
    """Configure file logging under the selected output directory.

    The scanner is not implemented yet; this helper centralizes the intended
    local-only log destination for future scan jobs.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / LOG_FILE_NAME

    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        force=True,
    )
    return log_path
