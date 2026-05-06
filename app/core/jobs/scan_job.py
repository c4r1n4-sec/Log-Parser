"""Local ingestion scan job orchestration."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.core.ingest.pipeline import IngestPipeline
from app.core.report.coverage import ArtifactCoverageRow, write_artifact_coverage
from app.core.report.hits import SearchHit, write_all_hits
from app.core.report.summary import write_summary_reports
from app.core.util.config import ExtractionLimits, extraction_limits, load_defaults
from app.core.util.logging import configure_scan_logging
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
    configure_scan_logging(workspace)

    if progress_callback is not None:
        progress_callback(f"Created workspace: {workspace}")

    config = load_defaults()
    active_limits = limits if limits is not None else extraction_limits(config)
    pipeline = IngestPipeline(
        workspace=workspace, limits=active_limits, progress_callback=progress_callback
    )
    rows = pipeline.process_inputs([Path(item) for item in inputs])

    hits = pipeline.hits

    coverage_csv = workspace / "artifact_coverage.csv"
    all_hits_csv = workspace / "all_hits.csv"
    write_artifact_coverage(rows, coverage_csv)
    write_all_hits(hits, all_hits_csv)
    report_outputs = write_summary_reports(rows, hits, workspace)

    if progress_callback is not None:
        progress_callback(f"Wrote artifact coverage: {coverage_csv}")
        progress_callback(f"Wrote all hits: {all_hits_csv}")
        progress_callback(f"Wrote triage report: {report_outputs.triage_report_html}")

    return ScanResult(
        workspace=workspace,
        coverage_csv=coverage_csv,
        all_hits_csv=all_hits_csv,
        findings_by_rule_csv=report_outputs.findings_by_rule_csv,
        findings_by_file_csv=report_outputs.findings_by_file_csv,
        missing_evidence_checklist_txt=report_outputs.missing_evidence_checklist_txt,
        triage_report_html=report_outputs.triage_report_html,
        triage_report_txt=report_outputs.triage_report_txt,
        rows=rows,
        hits=hits,
    )
