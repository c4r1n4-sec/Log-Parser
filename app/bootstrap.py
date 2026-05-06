"""Startup bootstrap helpers for the portable application."""

from __future__ import annotations

from app.core.util.paths import ensure_portable_directories


def bootstrap_application() -> None:
    """Prepare local portable directories without touching system state."""
    ensure_portable_directories()
