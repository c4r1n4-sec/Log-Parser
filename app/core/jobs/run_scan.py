"""Shared scan orchestration for GUI and drag/drop CLI entry points."""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path

from app.core.ingest.pipeline import IngestPipeline
from app.core.report.coverage import ArtifactCoverageRow, write_artifact_coverage
from app.core.report.hits import SearchHit, write_all_hits
from app.core.report.summary import write_summary_reports
from app.core.util.config import (
    ExtractionLimits,
    extraction_limits,
    load_defaults,
    report_options,
    scan_settings,
)
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
    include_generic_hits: bool | None = None
    max_examples_per_rule_in_report: int | None = None
    detected_case_number: str | None = None


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
    generic_hits_csv: Path | None = None
    findings_by_rule_csv: Path = Path()
    findings_by_file_csv: Path = Path()
    missing_evidence_checklist_txt: Path = Path()
    scan_summary_txt: Path = Path()
    scan_error_txt: Path | None = None
    failed: bool = False
    rows: list[ArtifactCoverageRow] = field(default_factory=list)
    hits: list[SearchHit] = field(default_factory=list)


def run_scan(inputs: list[str], output_dir: str, options: ScanOptions) -> ScanResult:
    """Run ingestion, App Control scanning, and report generation into ``output_dir``.

    This function owns the shared non-GUI scan path. Callers provide already chosen
    inputs and an exact output directory; the function creates that directory,
    processes every input it can, and writes all required reports there. If a fatal
    exception occurs, partial reports and scan_error.txt are still written.
    """
    workspace = Path(output_dir).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    configure_scan_logging(workspace)
    logger = logging.getLogger(__name__)

    coverage_csv = workspace / "artifact_coverage.csv"
    all_hits_csv = workspace / "all_hits.csv"
    generic_hits_csv = workspace / "generic_hits.csv"
    scan_summary_txt = workspace / "scan_summary.txt"
    scan_error_txt: Path | None = None
    rows: list[ArtifactCoverageRow] = []
    hits: list[SearchHit] = []
    rule_hits: list[SearchHit] = []
    generic_hits: list[SearchHit] = []
    summary_hits: list[SearchHit] = []
    written_generic_hits_csv = None
    report_outputs = None
    fatal_error = ""

    def phase(message: str) -> None:
        logger.info(message)
        if options.progress_callback is not None:
            options.progress_callback(message)

    phase("started scan")
    if options.detected_case_number:
        phase(f"detected case number: {options.detected_case_number}")
    phase(f"created output folder: {workspace}")

    config = load_defaults()
    active_limits = options.limits if options.limits is not None else extraction_limits(config)
    active_scan_settings = scan_settings(config)
    if options.limits is not None:
        active_scan_settings = replace(
            active_scan_settings, large_file_warning_bytes=active_limits.max_single_file_bytes
        )
    active_report_options = report_options(config)
    include_generic_hits = (
        options.include_generic_hits
        if options.include_generic_hits is not None
        else active_report_options.include_generic_hits
    )
    max_examples_per_rule = (
        options.max_examples_per_rule_in_report
        if options.max_examples_per_rule_in_report is not None
        else active_report_options.max_examples_per_rule_in_report
    )

    try:
        pipeline = IngestPipeline(
            workspace=workspace,
            limits=active_limits,
            scan_settings=active_scan_settings,
            progress_callback=options.progress_callback,
        )
        phase("started extraction")
        phase("started decoding")
        phase("started scanning")
        rows = pipeline.process_inputs([Path(item) for item in inputs])
        hits = pipeline.hits
        phase("finished extraction")
        phase("finished decoding")
        phase("finished scanning")
    except Exception as exc:  # fatal pipeline failure; always write partial reports below
        logger.exception("Fatal scan orchestration error")
        fatal_error = traceback.format_exc()
        scan_error_txt = workspace / "scan_error.txt"
        scan_error_txt.write_text(fatal_error, encoding="utf-8")
        rows = locals().get("pipeline").rows if "pipeline" in locals() else rows
        hits = locals().get("pipeline").hits if "pipeline" in locals() else hits
        rows.append(
            ArtifactCoverageRow(
                artifact_path="<scan orchestration>",
                original_input_path=";".join(inputs),
                extracted_from="",
                artifact_family="scan_error",
                identified_by="exception",
                review_mode="unreadable",
                line_numbers_supported=False,
                lines_or_rows_scanned=0,
                bytes_scanned=0,
                decoded_successfully=False,
                decoder_used="run_scan",
                decoder_status="scan-failed",
                encoding="",
                root_cause_value="",
                related_rule_ids="",
                limitations=f"Fatal scan error: {exc}",
            )
        )
    finally:
        phase("writing reports")
        rule_hits = _rule_hits(hits)
        generic_hits = _generic_hits(hits)
        summary_hits = _deduplicate_summary_hits(rule_hits)
        write_artifact_coverage(rows, coverage_csv)
        write_all_hits(rule_hits, all_hits_csv)
        if include_generic_hits:
            write_all_hits(generic_hits, generic_hits_csv)
            written_generic_hits_csv = generic_hits_csv
        report_outputs = write_summary_reports(
            rows,
            summary_hits,
            workspace,
            max_examples_per_rule=max_examples_per_rule,
            failure_details=fatal_error,
            max_report_raw_line_chars=active_report_options.max_report_raw_line_chars,
        )
        warnings = _collect_warnings(rows)
        severity_counts = _severity_counts(summary_hits)
        _write_scan_summary(
            scan_summary_txt,
            rows=rows,
            summary_hits=summary_hits,
            warnings=warnings,
            failed=bool(fatal_error),
            scan_error_txt=scan_error_txt,
        )
        phase("reports written")

    return ScanResult(
        output_dir=workspace,
        artifact_count=len(rows),
        scanned_count=_scanned_count(rows),
        hit_count=len(summary_hits),
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
        generic_hits_csv=written_generic_hits_csv,
        findings_by_rule_csv=report_outputs.findings_by_rule_csv,
        findings_by_file_csv=report_outputs.findings_by_file_csv,
        missing_evidence_checklist_txt=report_outputs.missing_evidence_checklist_txt,
        scan_summary_txt=scan_summary_txt,
        scan_error_txt=scan_error_txt,
        failed=bool(fatal_error),
        rows=rows,
        hits=rule_hits,
    )


def _write_scan_summary(
    output_path: Path,
    *,
    rows: list[ArtifactCoverageRow],
    summary_hits: list[SearchHit],
    warnings: list[str],
    failed: bool,
    scan_error_txt: Path | None,
) -> None:
    lines = [
        "Scan Summary",
        "============",
        f"Status: {'failed-partial-reports-written' if failed else 'completed'}",
        f"Files discovered: {len(rows)}",
        f"Files scanned: {_scanned_count(rows)}",
        f"Findings count: {len(summary_hits)}",
        f"Warnings: {len(warnings)}",
    ]
    if scan_error_txt is not None:
        lines.append(f"Scan error path: {scan_error_txt}")
    output_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

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


def _collect_warnings(rows: Iterable[ArtifactCoverageRow]) -> list[str]:
    warnings: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if row.limitations:
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


def _rule_hits(hits: Iterable[SearchHit]) -> list[SearchHit]:
    return [hit for hit in hits if hit.rule_id != "GENERIC_SEARCH"]


def _generic_hits(hits: Iterable[SearchHit]) -> list[SearchHit]:
    return [hit for hit in hits if hit.rule_id == "GENERIC_SEARCH"]


def _deduplicate_summary_hits(hits: Iterable[SearchHit]) -> list[SearchHit]:
    deduped: list[SearchHit] = []
    seen: set[tuple[str, str, str]] = set()
    for hit in hits:
        key = (hit.rule_id, hit.artifact_path, hit.raw_line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hit)
    return deduped
