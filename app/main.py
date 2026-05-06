"""Application entry point for TDSYNNEX Carbon Black Log Parser."""

from __future__ import annotations

import sys

from app.bootstrap import bootstrap_application

APP_NAME = "TDSYNNEX Carbon Black Log Parser"


def main() -> int:
    """Start the local desktop application."""
    bootstrap_application()

    from PySide6.QtWidgets import QApplication

    from app.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("TDSYNNEX")

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
