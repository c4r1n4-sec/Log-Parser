"""Configuration loading for the portable application."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.core.util.paths import app_root


@dataclass(frozen=True)
class ExtractionLimits:
    """Safety limits applied while recursively extracting archives."""

    max_archive_depth: int
    max_total_extracted_bytes: int
    max_single_file_bytes: int


def load_defaults() -> dict[str, Any]:
    """Load the bundled default configuration from source or portable layout."""
    root = app_root()
    candidates = [
        root / "config" / "defaults.json",
        root / "app" / "config" / "defaults.json",
    ]
    for config_path in candidates:
        if config_path.exists():
            with config_path.open("r", encoding="utf-8") as config_file:
                return json.load(config_file)
    raise FileNotFoundError("Unable to locate defaults.json in portable or source config path.")


def extraction_limits(config: dict[str, Any] | None = None) -> ExtractionLimits:
    """Return archive extraction limits from configuration."""
    defaults = config if config is not None else load_defaults()
    extraction = defaults.get("extraction", {})
    return ExtractionLimits(
        max_archive_depth=int(extraction.get("max_archive_depth", 3)),
        max_total_extracted_bytes=int(extraction.get("max_total_extracted_bytes", 1_073_741_824)),
        max_single_file_bytes=int(extraction.get("max_single_file_bytes", 268_435_456)),
    )
