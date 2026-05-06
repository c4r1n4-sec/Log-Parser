"""Minimal PySide6 main window for local ingestion scans."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.core.jobs.scan_job import run_ingestion_scan
from app.core.util.paths import default_output_dir

if TYPE_CHECKING:
    from PySide6.QtGui import QDragEnterEvent, QDropEvent

WINDOW_TITLE = "TDSYNNEX Carbon Black Log Parser"


class DropArea(QFrame):
    """Drag/drop area that forwards local file and folder paths to the window."""

    def __init__(self, paths_callback) -> None:
        super().__init__()
        self.paths_callback = paths_callback
        self.setAcceptDrops(True)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setObjectName("dropArea")

        layout = QVBoxLayout(self)
        label = QLabel("Drag and drop Carbon Black log files or folders here")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802 - Qt override name
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802 - Qt override name
        paths = [Path(url.toLocalFile()) for url in event.mimeData().urls() if url.isLocalFile()]
        if paths:
            self.paths_callback(paths)
            event.acceptProposedAction()
        else:
            event.ignore()


class MainWindow(QMainWindow):
    """Small placeholder shell connected to the ingestion/classification pipeline."""

    def __init__(self) -> None:
        super().__init__()
        self.selected_inputs: list[Path] = []
        self.output_folder = default_output_dir()
        self.latest_scan_output: Path | None = None
        self.progress_label: QLabel
        self.input_list: QListWidget

        self.setWindowTitle(WINDOW_TITLE)
        self.resize(900, 560)
        self.setCentralWidget(self._build_content())
        self.statusBar().showMessage("Ready")
        self._refresh_inputs()

    def _build_content(self) -> QWidget:
        root = QWidget()
        layout = QVBoxLayout(root)

        heading = QLabel(WINDOW_TITLE)
        heading.setObjectName("heading")
        heading.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(heading)

        button_row = QHBoxLayout()
        self.add_files_button = QPushButton("Add Files")
        self.add_folder_button = QPushButton("Add Folder")
        self.select_output_button = QPushButton("Select Output Folder")
        self.start_scan_button = QPushButton("Start Scan")
        self.open_output_button = QPushButton("Open Output Folder")

        for button in (
            self.add_files_button,
            self.add_folder_button,
            self.select_output_button,
            self.start_scan_button,
            self.open_output_button,
        ):
            button_row.addWidget(button)
        layout.addLayout(button_row)

        self.add_files_button.clicked.connect(self._add_files)
        self.add_folder_button.clicked.connect(self._add_folder)
        self.select_output_button.clicked.connect(self._select_output_folder)
        self.start_scan_button.clicked.connect(self._start_scan)
        self.open_output_button.clicked.connect(self._open_output_folder)

        layout.addWidget(DropArea(self._add_paths), stretch=1)

        self.input_list = QListWidget()
        layout.addWidget(self.input_list)

        self.progress_label = QLabel("Status: Waiting for input. Progress: 0%")
        layout.addWidget(self.progress_label)

        return root

    def _add_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Add Files")
        self._add_paths([Path(file_name) for file_name in files])

    def _add_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Add Folder")
        if folder:
            self._add_paths([Path(folder)])

    def _select_output_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self, "Select Output Folder", str(self.output_folder)
        )
        if folder:
            self.output_folder = Path(folder)
            self._set_progress(f"Output folder selected: {self.output_folder}")

    def _add_paths(self, paths: list[Path]) -> None:
        existing = {path.resolve() for path in self.selected_inputs if path.exists()}
        for path in paths:
            resolved = path.expanduser().resolve()
            if resolved not in existing:
                self.selected_inputs.append(resolved)
                existing.add(resolved)
        self._refresh_inputs()
        self._set_progress(f"Ready. {len(self.selected_inputs)} input path(s) selected.")

    def _refresh_inputs(self) -> None:
        self.input_list.clear()
        if not self.selected_inputs:
            self.input_list.addItem("No inputs selected.")
            return
        for path in self.selected_inputs:
            self.input_list.addItem(str(path))

    def _start_scan(self) -> None:
        if not self.selected_inputs:
            self._set_progress("Select files or folders before starting a scan.")
            return

        self.start_scan_button.setEnabled(False)
        self._set_progress("Starting scan. Progress: creating workspace...")
        try:
            result = run_ingestion_scan(
                self.selected_inputs,
                output_dir=self.output_folder,
                progress_callback=self._set_progress,
            )
        except Exception as exc:  # keep the GUI from crashing on unexpected local input issues
            self._set_progress(f"Scan failed: {exc}")
            self.statusBar().showMessage("Scan failed")
        else:
            self.latest_scan_output = result.workspace
            self._set_progress(
                "Scan complete. Progress: 100%. "
                f"Coverage: {result.coverage_csv}; Hits: {result.all_hits_csv}"
            )
            self.statusBar().showMessage(f"Output: {result.workspace}")
        finally:
            self.start_scan_button.setEnabled(True)

    def _open_output_folder(self) -> None:
        folder = self.latest_scan_output or self.output_folder
        folder.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def _set_progress(self, message: str) -> None:
        self.progress_label.setText(message)
        self.statusBar().showMessage(message)
        QApplication.processEvents()
