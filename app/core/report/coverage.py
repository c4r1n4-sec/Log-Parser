"""Artifact coverage CSV models and writer."""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from pathlib import Path

ARTIFACT_COVERAGE_FIELDS = [
    "artifact_path",
    "original_input_path",
    "extracted_from",
    "artifact_family",
    "identified_by",
    "review_mode",
    "line_numbers_supported",
    "lines_or_rows_scanned",
    "bytes_scanned",
    "decoded_successfully",
    "decoder_used",
    "decoder_status",
    "encoding",
    "root_cause_value",
    "related_rule_ids",
    "limitations",
]


@dataclass
class ArtifactCoverageRow:
    """One row in artifact_coverage.csv."""

    artifact_path: str
    original_input_path: str
    extracted_from: str
    artifact_family: str
    identified_by: str
    review_mode: str
    line_numbers_supported: bool
    lines_or_rows_scanned: int
    bytes_scanned: int
    decoded_successfully: bool
    decoder_used: str
    decoder_status: str
    encoding: str
    root_cause_value: str
    related_rule_ids: str
    limitations: str


def write_artifact_coverage(rows: list[ArtifactCoverageRow], output_path: Path) -> None:
    """Write coverage rows to artifact_coverage.csv."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=ARTIFACT_COVERAGE_FIELDS, quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))
