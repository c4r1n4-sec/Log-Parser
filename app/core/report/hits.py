"""Search hit CSV models and writer."""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from pathlib import Path

ALL_HITS_FIELDS = [
    "hit_id",
    "rule_id",
    "severity",
    "product",
    "issue_category",
    "component",
    "artifact_path",
    "line_number",
    "byte_offset",
    "timestamp",
    "matched_text",
    "raw_line",
    "context_before",
    "context_after",
    "match_type",
    "scanner",
    "encoding",
    "kb_candidate_ids",
]


@dataclass
class SearchHit:
    """One row in all_hits.csv."""

    hit_id: str
    rule_id: str
    severity: str
    product: str
    issue_category: str
    component: str
    artifact_path: str
    line_number: str
    byte_offset: str
    timestamp: str
    matched_text: str
    raw_line: str
    context_before: str
    context_after: str
    match_type: str
    scanner: str
    encoding: str
    kb_candidate_ids: str


def make_hit(
    *,
    artifact_path: Path,
    matched_text: str,
    raw_line: str,
    context_before: str,
    context_after: str,
    match_type: str,
    scanner: str,
    encoding: str,
    line_number: int | None = None,
    byte_offset: int | None = None,
    rule_id: str = "GENERIC_SEARCH",
    severity: str = "Info",
    product: str = "Unknown",
    issue_category: str = "Generic keyword hit",
    component: str = "Unknown",
    kb_candidate_ids: str = "",
) -> SearchHit:
    """Create a search hit row with deterministic rule metadata."""
    return SearchHit(
        hit_id="",
        rule_id=rule_id,
        severity=severity,
        product=product,
        issue_category=issue_category,
        component=component,
        artifact_path=str(artifact_path),
        line_number=str(line_number) if line_number is not None else "",
        byte_offset=str(byte_offset) if byte_offset is not None else "",
        timestamp="",
        matched_text=matched_text,
        raw_line=raw_line,
        context_before=context_before,
        context_after=context_after,
        match_type=match_type,
        scanner=scanner,
        encoding=encoding,
        kb_candidate_ids=kb_candidate_ids,
    )


def write_all_hits(hits: list[SearchHit], output_path: Path) -> None:
    """Write all search hits to all_hits.csv."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=ALL_HITS_FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for index, hit in enumerate(hits, start=1):
            row = asdict(hit)
            row["hit_id"] = f"H{index:06d}"
            writer.writerow(row)
