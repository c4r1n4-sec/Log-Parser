"""Basic startup smoke tests for the initial skeleton."""

from __future__ import annotations

import pytest
from app.main import APP_NAME


def test_application_name_constant() -> None:
    assert APP_NAME == "TDSYNNEX Carbon Black Log Parser"


def test_window_title_matches_application_name() -> None:
    pytest.importorskip(
        "PySide6.QtGui",
        reason="PySide6 Qt GUI libraries are not available in this environment",
        exc_type=ImportError,
    )
    from app.ui.main_window import WINDOW_TITLE

    assert WINDOW_TITLE == APP_NAME
