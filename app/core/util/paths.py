"""Portable path helpers.

All paths are resolved relative to the extracted application folder so the
application can run without installation or administrator privileges.
"""

from __future__ import annotations

import sys
from pathlib import Path


def app_root() -> Path:
    """Return the root folder for source or PyInstaller one-folder execution."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[3]


def default_output_dir() -> Path:
    """Return the default local output directory inside the portable folder."""
    return app_root() / "output"


def ensure_portable_directories() -> None:
    """Create local writable directories used by the portable app."""
    default_output_dir().mkdir(parents=True, exist_ok=True)
