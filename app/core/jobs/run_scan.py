"""Shared scan orchestration for GUI and drag/drop CLI entry points."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from app.core.ingest.pipeline import IngestPipeline
from app.core.report.coverage import ArtifactCoverageRow, write_artifact_coverage
from app.core.report.hits import SearchHit, write_all_hits
from app.core.report.summary import write_summary_reports
from app.core.util.config import ExtractionLimits, extraction_limits, load_defaults
from app.core.util.logging import configure_scan_logging

ProgressCallback = Callable[[str], None]

REQUIRED_REPORT_NAMES = (
    "artifact_coverage.csv",
    "all_hits.csv",
    "findings_by_rule.csv",
    "findings_by_file.csv",
    "missing_evidence_checklist.txt",
    "triage_report.html",
    "triage_report.txt",
    "scan_summary.txt",
)


@dataclass(frozen=True)
class ScanOptions:
    """Options for the shared local scan pipeline."""

    progress_callback: ProgressCallback | None = None
    limits: ExtractionLimits | None = None


@dataclass(frozen=True)
class ScanResult:
    """Summary and report paths produced by a local scan."""

    output_dir: Path
    artifact_count: int
    scanned_count: int
    hit_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    warnings: list[str] = field(default_factory=list)
    report_html_path: Path = Path()
    report_txt_path: Path = Path()
    coverage_csv: Path = Path()
    all_hits_csv: Path = Path()
    findings_by_rule_csv: Path = Path()
    findings_by_file_csv: Path = Path()
    missing_evidence_checklist_txt: Path = Path()
    scan_summary_txt: Path = Path()
    rows: list[ArtifactCoverageRow] = field(default_factory=list)
    hits: list[SearchHit] = field(default_factory=list)


def run_scan(inputs: list[str], output_dir: str, options: ScanOptions) -> ScanResult:
    """Run ingestion, App Control scanning, and report generation into ``output_dir``.

    This function owns the shared non-GUI scan path. Callers provide already chosen
    inputs and an exact output directory; the function creates that directory,
    processes every input it can, and writes all required reports there.
    """
    workspace = Path(output_dir).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    configure_scan_logging(workspace)

    if options.progress_callback is not None:
        options.progress_callback(f"Created output folder: {workspace}")

    config = load_defaults()
    active_limits = options.limits if options.limits is not None else extraction_limits(config)
    pipeline = IngestPipeline(
        workspace=workspace,
        limits=active_limits,
        progress_callback=options.progress_callback,
    )
    rows = pipeline.process_inputs([Path(item) for item in inputs])
    hits = pipeline.hits

    coverage_csv = workspace / "artifact_coverage.csv"
    all_hits_csv = workspace / "all_hits.csv"
    write_artifact_coverage(rows, coverage_csv)
    write_all_hits(hits, all_hits_csv)
    report_outputs = write_summary_reports(rows, hits, workspace)

    warnings = _collect_warnings(rows)
    severity_counts = _severity_counts(hits)
    scan_summary_txt = workspace / "scan_summary.txt"
    _write_scan_summary(scan_summary_txt, rows, hits, warnings)

    if options.progress_callback is not None:
        options.progress_callback(f"Wrote artifact coverage: {coverage_csv}")
        options.progress_callback(f"Wrote all hits: {all_hits_csv}")
        options.progress_callback(f"Wrote triage report: {report_outputs.triage_report_html}")

    return ScanResult(
        output_dir=workspace,
        artifact_count=len(rows),
        scanned_count=_scanned_count(rows),
        hit_count=len(hits),
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        info_count=severity_counts["info"],
        warnings=warnings,
        report_html_path=report_outputs.triage_report_html,
        report_txt_path=report_outputs.triage_report_txt,
        coverage_csv=coverage_csv,
        all_hits_csv=all_hits_csv,
        findings_by_rule_csv=report_outputs.findings_by_rule_csv,
        findings_by_file_csv=report_outputs.findings_by_file_csv,
        missing_evidence_checklist_txt=report_outputs.missing_evidence_checklist_txt,
        scan_summary_txt=scan_summary_txt,
        rows=rows,
        hits=hits,
    )


def _scanned_count(rows: Iterable[ArtifactCoverageRow]) -> int:
    return sum(
        1
        for row in rows
        if row.review_mode in {"stream-scanned", "binary-string-scanned"}
        or row.lines_or_rows_scanned > 0
        or row.bytes_scanned > 0
    )


def _severity_counts(hits: Iterable[SearchHit]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for hit in hits:
        severity = hit.severity.lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["info"] += 1
    return counts


def _write_scan_summary(
    output_path: Path, rows: list[ArtifactCoverageRow], hits: list[SearchHit], warnings: list[str]
) -> None:
    lines = [
        "Scan summary",
        "============",
        f"Artifacts reviewed: {len(rows)}",
        f"Findings count: {len(hits)}",
        f"Warnings: {len(warnings)}",
    ]
    if warnings:
        lines.extend(["", "Warnings", "--------"])
        lines.extend(f"- {warning}" for warning in warnings)
    output_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _collect_warnings(rows: Iterable[ArtifactCoverageRow]) -> list[str]:
    warnings: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if row.decoder_status == "password-required":
            warning = f"Encrypted ZIP member skipped: {row.artifact_path}"
        elif row.limitations:
            warning = f"{row.artifact_path}: {row.limitations}"
        elif row.decoder_status in {
            "archive-loop-detected",
            "scan-failed",
            "skipped-by-policy",
            "skipped-symlink-input",
            "unreadable",
            "unsafe-archive-path-refused",
        }:
            warning = f"{row.artifact_path}: {row.decoder_status}"
        else:
            continue
        if warning not in seen:
            seen.add(warning)
            warnings.append(warning)
    return warnings
