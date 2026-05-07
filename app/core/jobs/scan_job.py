"""Local ingestion scan job orchestration."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.core.jobs.run_scan import ScanOptions, run_scan
from app.core.report.coverage import ArtifactCoverageRow
from app.core.report.hits import SearchHit
from app.core.util.config import ExtractionLimits
from app.core.util.paths import default_output_dir

ProgressCallback = Callable[[str], None]


@dataclass(frozen=True)
class ScanResult:
    """Result details for a completed local ingestion scan."""

    workspace: Path
    coverage_csv: Path
    all_hits_csv: Path
    findings_by_rule_csv: Path
    findings_by_file_csv: Path
    missing_evidence_checklist_txt: Path
    scan_summary_txt: Path
    triage_report_html: Path
    triage_report_txt: Path
    rows: list[ArtifactCoverageRow]
    hits: list[SearchHit]


def create_scan_workspace(output_dir: Path | None = None) -> Path:
    """Create a timestamped per-scan workspace under the selected output folder."""
    base_output = output_dir if output_dir is not None else default_output_dir()
    scans_dir = base_output / "scans"
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    workspace = scans_dir / timestamp
    suffix = 1
    while workspace.exists():
        workspace = scans_dir / f"{timestamp}-{suffix}"
        suffix += 1
    workspace.mkdir(parents=True, exist_ok=False)
    return workspace


def run_ingestion_scan(
    inputs: Iterable[Path],
    output_dir: Path | None = None,
    progress_callback: ProgressCallback | None = None,
    limits: ExtractionLimits | None = None,
) -> ScanResult:
    """Run the local ingestion/classification pipeline and write artifact coverage."""
    resolved_output = output_dir if output_dir is not None else default_output_dir()
    workspace = create_scan_workspace(resolved_output)
    shared_result = run_scan(
        [str(item) for item in inputs],
        str(workspace),
        ScanOptions(progress_callback=progress_callback, limits=limits),
    )

    return ScanResult(
        workspace=workspace,
        coverage_csv=shared_result.coverage_csv,
        all_hits_csv=shared_result.all_hits_csv,
        findings_by_rule_csv=shared_result.findings_by_rule_csv,
        findings_by_file_csv=shared_result.findings_by_file_csv,
        missing_evidence_checklist_txt=shared_result.missing_evidence_checklist_txt,
        scan_summary_txt=shared_result.scan_summary_txt,
        triage_report_html=shared_result.report_html_path,
        triage_report_txt=shared_result.report_txt_path,
        rows=shared_result.rows,
        hits=shared_result.hits,
    )
