"""Basic startup smoke tests for the initial skeleton."""

from __future__ import annotations

import importlib.util

import pytest
from app.main import APP_NAME


def test_application_name_constant() -> None:
    assert APP_NAME == "TDSYNNEX Carbon Black Log Parser"


@pytest.mark.skipif(importlib.util.find_spec("PySide6") is None, reason="PySide6 is not installed")
def test_window_title_matches_application_name() -> None:
    from app.ui.main_window import WINDOW_TITLE

    assert WINDOW_TITLE == APP_NAME
