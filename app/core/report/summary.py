"""Derived findings and local triage report generation."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.report.coverage import ArtifactCoverageRow
from app.core.report.hits import SearchHit
from app.core.rules.app_control import AppControlRule, load_app_control_rules
from app.core.util.paths import app_root

FINDINGS_BY_RULE_FIELDS = [
    "rule_id",
    "product",
    "issue_category",
    "component",
    "severity",
    "hit_count",
    "artifacts_hit",
    "first_seen_file",
    "first_seen_line",
    "kb_candidate_ids",
    "required_evidence_status",
    "missing_evidence",
    "false_positive_cautions",
]

FINDINGS_BY_FILE_FIELDS = [
    "artifact_path",
    "artifact_family",
    "hit_count",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "info_count",
    "matched_rule_ids",
    "limitations",
]

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
APPCONTROL_PRODUCT = "Carbon Black App Control"

FALSE_POSITIVE_REPORT_CAUTIONS = [
    "CDC unavailable alert is not automatically a network failure.",
    "No services.bit9.com traffic in a short PCAP does not prove the network is bad.",
    "Connected(Waiting) is not automatically a firewall issue.",
    (
        "GetSslError or GetWinHttpError must be correlated with certificate, "
        "proxy, and server-address evidence."
    ),
    "Publisher-validation blocks may be Windows Crypto, trust-store, or revocation related.",
    "Communication-key overuse is often a 443 / certificate-distribution issue, not 41002.",
    "Kernel assertions are usually low-value unless repeated heavily or tied to user impact.",
    "Still analyzing blocks can be normal unless recurring and user-impacting.",
    "Timeout tuning is not a fix for slow SQL.",
]

MISSING_EVIDENCE_BY_FAMILY = {
    "Disconnected agent missing evidence": [
        "trace.bt9",
        "dascli status",
        "dascli server",
        "port 41002 evidence",
        "port 443 evidence",
        "DNS/proxy output",
    ],
    "CDC / File Reputation missing evidence": [
        "ReporterLog",
        "ParityReporter.exe check output",
        "ReporterConnectivityError output",
        "services.bit9.com / 443 evidence",
        "SQLTrace if timeout suspected",
    ],
    "SQL / performance missing evidence": [
        "SQLTrace",
        "CB Analysis Script output",
        "ReporterLog or PHPErrors",
        "SQL/version/database scale evidence",
    ],
    "Policy block missing evidence": [
        "full block event text",
        "file hash",
        "rule name",
        "dascli find output",
        "publisher/certificate context",
    ],
    "Tamper missing evidence": [
        "tamper event wording",
        "process name",
        "protected path or registry key",
    ],
    "Upgrade missing evidence": [
        "ServerInstall log",
        "version/build",
        "Reporter startup output",
    ],
}

NEGATIVE_SEARCHES = [
    ("No trace.bt9 found", {"agent_trace_bt9"}, None),
    ("No ReporterLog found", {"reporter_log"}, None),
    ("No SQLTrace found", {"sql_trace", "reporter_log", "php_errors", "cb_analysis_output"}, None),
    ("No GetWinHttpError found", {"agent_trace_bt9", "server_bt9"}, "GetWinHttpError"),
    ("No GetSslError found", {"agent_trace_bt9", "server_bt9"}, "GetSslError"),
    ("No METHOD_SECURE_MESSAGE found", {"agent_trace_bt9", "server_bt9"}, "METHOD_SECURE_MESSAGE"),
    (
        "No SSL Key Pinning mismatch found",
        {"agent_trace_bt9", "server_bt9"},
        "SSL Key Pinning mismatch",
    ),
    (
        "No services.bit9.com evidence found",
        {"reporter_log", "server_bt9", "agent_trace_bt9"},
        "services.bit9.com",
    ),
    (
        "No ReporterConnectivityError found",
        {"reporter_log", "server_bt9"},
        "ReporterConnectivityError",
    ),
    ("No ValidationError found", {"server_bt9", "agent_trace_bt9", "text_log"}, "ValidationError"),
    ("No tamper wording found", {"agent_trace_bt9", "server_bt9", "text_log"}, "tamper"),
    (
        "No AppCWebServer evidence found",
        {"cb_analysis_output", "sql_trace", "php_errors", "reporter_log"},
        "AppCWebServer",
    ),
    (
        "No add_server_role evidence found",
        {"cb_analysis_output", "sql_trace", "php_errors", "reporter_log"},
        "add_server_role",
    ),
    (
        "No backlog overflow signature found",
        {"server_bt9", "sql_trace"},
        "Arithmetic overflow error converting IDENTITY",
    ),
]


@dataclass
class FindingByRule:
    """Aggregated finding row grouped by rule."""

    rule_id: str
    product: str
    issue_category: str
    component: str
    severity: str
    hit_count: int
    artifacts_hit: str
    first_seen_file: str
    first_seen_line: str
    kb_candidate_ids: str
    required_evidence_status: str
    missing_evidence: str
    false_positive_cautions: str


@dataclass
class FindingByFile:
    """Aggregated finding row grouped by file."""

    artifact_path: str
    artifact_family: str
    hit_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    matched_rule_ids: str
    limitations: str


@dataclass(frozen=True)
class ReportOutputs:
    """Paths produced by summary report generation."""

    findings_by_rule_csv: Path
    findings_by_file_csv: Path
    missing_evidence_checklist_txt: Path
    triage_report_html: Path
    triage_report_txt: Path


def write_summary_reports(
    rows: list[ArtifactCoverageRow],
    hits: list[SearchHit],
    workspace: Path,
    max_examples_per_rule: int = 25,
    failure_details: str = "",
    max_report_raw_line_chars: int = 2_000,
) -> ReportOutputs:
    """Write derived finding summaries and local reports."""
    rules_by_id = {rule.rule_id: rule for rule in load_app_control_rules()}
    kb_titles = _load_kb_titles()
    findings_by_rule = build_findings_by_rule(hits, rules_by_id)
    findings_by_file = build_findings_by_file(rows, hits)
    missing_checklist = build_missing_evidence_checklist(rows, hits)
    negative_searches = build_negative_searches(rows)

    findings_by_rule_csv = workspace / "findings_by_rule.csv"
    findings_by_file_csv = workspace / "findings_by_file.csv"
    checklist_txt = workspace / "missing_evidence_checklist.txt"
    report_html = workspace / "triage_report.html"
    report_txt = workspace / "triage_report.txt"

    _write_findings_by_rule(findings_by_rule, findings_by_rule_csv)
    _write_findings_by_file(findings_by_file, findings_by_file_csv)
    checklist_txt.write_text(missing_checklist, encoding="utf-8")
    report_txt.write_text(
        _render_text_report(
            rows,
            hits,
            findings_by_rule,
            findings_by_file,
            missing_checklist,
            negative_searches,
            kb_titles,
            max_examples_per_rule,
            failure_details,
            max_report_raw_line_chars,
        ),
        encoding="utf-8",
    )
    report_html.write_text(
        _render_html_report(
            rows,
            hits,
            findings_by_rule,
            findings_by_file,
            missing_checklist,
            negative_searches,
            kb_titles,
            max_examples_per_rule,
            failure_details,
            max_report_raw_line_chars,
        ),
        encoding="utf-8",
    )

    return ReportOutputs(
        findings_by_rule_csv=findings_by_rule_csv,
        findings_by_file_csv=findings_by_file_csv,
        missing_evidence_checklist_txt=checklist_txt,
        triage_report_html=report_html,
        triage_report_txt=report_txt,
    )


def build_findings_by_rule(
    hits: list[SearchHit], rules_by_id: dict[str, AppControlRule]
) -> list[FindingByRule]:
    """Aggregate hits by rule ID."""
    grouped: dict[str, list[SearchHit]] = defaultdict(list)
    for hit in hits:
        if hit.rule_id in rules_by_id:
            grouped[hit.rule_id].append(hit)

    findings: list[FindingByRule] = []
    for rule_id, rule_hits in grouped.items():
        first = rule_hits[0]
        rule = rules_by_id.get(rule_id)
        artifacts = sorted({hit.artifact_path for hit in rule_hits})
        findings.append(
            FindingByRule(
                rule_id=rule_id,
                product=first.product,
                issue_category=first.issue_category,
                component=first.component,
                severity=first.severity,
                hit_count=len(rule_hits),
                artifacts_hit=";".join(artifacts),
                first_seen_file=first.artifact_path,
                first_seen_line=first.line_number or first.byte_offset,
                kb_candidate_ids=first.kb_candidate_ids,
                required_evidence_status=_required_evidence_status(rule_id, rule),
                missing_evidence=rule.missing_evidence
                if rule
                else "Not applicable for generic search.",
                false_positive_cautions=(
                    rule.false_positive_cautions if rule else "Generic keyword hit; review context."
                ),
            )
        )
    return sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.rule_id))


def build_findings_by_file(
    rows: list[ArtifactCoverageRow], hits: list[SearchHit]
) -> list[FindingByFile]:
    """Aggregate hit counts and rule IDs by artifact path."""
    rows_by_path = {row.artifact_path: row for row in rows}
    hits_by_path: dict[str, list[SearchHit]] = defaultdict(list)
    for hit in hits:
        if hit.rule_id != "GENERIC_SEARCH":
            hits_by_path[hit.artifact_path].append(hit)

    findings: list[FindingByFile] = []
    for artifact_path in sorted(rows_by_path):
        row = rows_by_path[artifact_path]
        file_hits = hits_by_path.get(artifact_path, [])
        severity_counts = Counter(hit.severity.lower() for hit in file_hits)
        findings.append(
            FindingByFile(
                artifact_path=artifact_path,
                artifact_family=row.artifact_family,
                hit_count=len(file_hits),
                critical_count=severity_counts["critical"],
                high_count=severity_counts["high"],
                medium_count=severity_counts["medium"],
                low_count=severity_counts["low"],
                info_count=severity_counts["info"],
                matched_rule_ids=";".join(sorted({hit.rule_id for hit in file_hits})),
                limitations=row.limitations,
            )
        )
    return findings


def build_missing_evidence_checklist(rows: list[ArtifactCoverageRow], hits: list[SearchHit]) -> str:
    """Build the missing evidence checklist grouped by App Control issue family."""
    available = _available_evidence(rows, hits)
    empty_trace_present = _empty_trace_present(rows)
    lines = [
        "Missing Evidence Checklist",
        "===========================",
        "Labels below are missing evidence prompts, not final-cause statements.",
        "",
    ]
    for family, items in MISSING_EVIDENCE_BY_FAMILY.items():
        lines.append(family)
        lines.append("-" * len(family))
        for item in items:
            if "trace.bt9" in item.lower() and empty_trace_present:
                lines.append("- [present-empty] trace.bt9 present but empty")
                continue
            status = "observed" if _evidence_item_observed(item, available) else "missing"
            lines.append(f"- [{status}] {item}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_negative_searches(rows: list[ArtifactCoverageRow]) -> list[str]:
    """Generate valid negative searches only for scanned relevant artifacts."""
    scanned_by_family: dict[str, list[ArtifactCoverageRow]] = defaultdict(list)
    for row in rows:
        if row.review_mode in {"stream-scanned", "binary-string-scanned"}:
            scanned_by_family[row.artifact_family].append(row)

    negatives: list[str] = []
    for message, relevant_families, pattern in NEGATIVE_SEARCHES:
        relevant_rows = [
            row for family in relevant_families for row in scanned_by_family.get(family, [])
        ]
        if not relevant_rows:
            continue
        if pattern is None:
            target_family = _negative_target_family(message)
            if target_family and target_family not in scanned_by_family:
                negatives.append(message)
            continue
        if not _pattern_seen_in_rows(pattern, relevant_rows):
            negatives.append(message)
    return negatives


def _negative_target_family(message: str) -> str | None:
    if "trace.bt9" in message:
        return "agent_trace_bt9"
    if "ReporterLog" in message:
        return "reporter_log"
    if "SQLTrace" in message:
        return "sql_trace"
    return None


def _write_findings_by_rule(findings: list[FindingByRule], output_path: Path) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=FINDINGS_BY_RULE_FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def _write_findings_by_file(findings: list[FindingByFile], output_path: Path) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=FINDINGS_BY_FILE_FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def _render_text_report(
    rows: list[ArtifactCoverageRow],
    hits: list[SearchHit],
    findings_by_rule: list[FindingByRule],
    findings_by_file: list[FindingByFile],
    missing_checklist: str,
    negative_searches: list[str],
    kb_titles: dict[str, str],
    max_examples_per_rule: int = 25,
    failure_details: str = "",
    max_report_raw_line_chars: int = 2_000,
) -> str:
    lines = [
        "TDSYNNEX Carbon Black Log Parser Triage Report",
        "================================================",
        (
            "Terminology: Observed evidence, likely issue family, KB candidate, "
            "missing evidence, limitation."
        ),
        "This report records observations only and does not make final-cause conclusions.",
        "",
        *(
            ["Scan failure", "------------", failure_details.rstrip(), ""]
            if failure_details
            else []
        ),
        "Scan summary",
        "------------",
        f"Artifacts reviewed: {len(rows)}",
        f"App Control findings observed: {len(hits)}",
        f"App Control rules observed: {len({hit.rule_id for hit in hits})}",
        "",
        "Product detected",
        "----------------",
        _product_detected(hits),
        "",
        "Artifacts reviewed",
        "------------------",
    ]
    lines.extend(
        f"- {finding.artifact_path} ({finding.artifact_family}) hits={finding.hit_count}"
        for finding in findings_by_file
    )
    lines.extend(["", "Artifacts not decoded", "---------------------"])
    not_decoded = [
        row for row in rows if not row.decoded_successfully and row.review_mode != "stream-scanned"
    ]
    if not_decoded:
        lines.extend(_artifact_line(row) for row in not_decoded)
    else:
        lines.append("- None")

    for severity in ("Critical", "High", "Medium"):
        lines.extend(["", f"{severity} App Control findings", "-" * (len(severity) + 30)])
        severity_hits = [hit for hit in hits if hit.severity == severity]
        if not severity_hits:
            lines.append("- None")
        for hit in _cap_hits_by_rule(severity_hits, max_examples_per_rule):
            if hit is None:
                lines.append("- Additional hits omitted from report. See all_hits.csv.")
            else:
                lines.extend(_text_finding_lines(hit, max_report_raw_line_chars))

    lines.extend(["", "Missing evidence", "----------------", missing_checklist.rstrip()])
    lines.extend(["", "Negative searches", "-----------------"])
    lines.extend(f"- {item}" for item in negative_searches) if negative_searches else lines.append(
        "- None"
    )
    lines.extend(["", "KB candidates", "-------------"])
    lines.extend(_kb_lines(hits, kb_titles))
    lines.extend(["", "False-positive cautions", "-----------------------"])
    lines.extend(f"- {item}" for item in _relevant_false_positive_cautions(hits))
    lines.extend(["", "Warnings", "--------"])
    lines.extend(_warnings(rows))
    lines.extend(["", "Limitations", "-----------"])
    lines.extend(_limitations())
    return "\n".join(lines).rstrip() + "\n"


def _render_html_report(
    rows: list[ArtifactCoverageRow],
    hits: list[SearchHit],
    findings_by_rule: list[FindingByRule],
    findings_by_file: list[FindingByFile],
    missing_checklist: str,
    negative_searches: list[str],
    kb_titles: dict[str, str],
    max_examples_per_rule: int = 25,
    failure_details: str = "",
    max_report_raw_line_chars: int = 2_000,
) -> str:
    css = """
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #222; }
section { margin-bottom: 28px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; }
th, td { border: 1px solid #ccc; padding: 6px; vertical-align: top; }
th { background: #f3f3f3; }
pre { white-space: pre-wrap; background: #f7f7f7; padding: 8px; }
.finding { border: 1px solid #ddd; padding: 10px; margin: 8px 0; }
""".strip()
    sections = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<title>TDSYNNEX Carbon Black Log Parser Triage Report</title>",
        f"<style>{css}</style></head><body>",
        "<h1>TDSYNNEX Carbon Black Log Parser Triage Report</h1>",
        (
            "<p><strong>Terminology:</strong> Observed evidence, likely issue family, "
            "KB candidate, missing evidence, limitation. This report records observations "
            "only and does not make final-cause conclusions.</p>"
        ),
        *(
            [_html_section("Scan failure", f"<pre>{html.escape(failure_details.rstrip())}</pre>")]
            if failure_details
            else []
        ),
        _html_section(
            "Scan summary",
            f"<p>Artifacts reviewed: {len(rows)}<br>"
            f"App Control findings observed: {len(hits)}<br>"
            f"App Control rules observed: {len({hit.rule_id for hit in hits})}</p>",
        ),
        _html_section("Product detected", f"<p>{html.escape(_product_detected(hits))}</p>"),
        _html_section("Artifacts reviewed", _html_findings_by_file(findings_by_file)),
        _html_section("Artifacts not decoded", _html_artifacts_not_decoded(rows)),
    ]
    for severity in ("Critical", "High", "Medium"):
        sections.append(
            _html_section(
                f"{severity} App Control findings",
                _html_hits_with_rule_cap(
                    [hit for hit in hits if hit.severity == severity],
                    max_examples_per_rule,
                    max_report_raw_line_chars,
                ),
            )
        )
    sections.extend(
        [
            _html_section("Missing evidence", f"<pre>{html.escape(missing_checklist)}</pre>"),
            _html_section("Negative searches", _html_list(negative_searches)),
            _html_section("Warnings", _html_list(_warnings(rows))),
            _html_section("KB candidates", _html_list(_kb_lines(hits, kb_titles))),
            _html_section(
                "False-positive cautions", _html_list(_relevant_false_positive_cautions(hits))
            ),
            _html_section("Limitations", _html_list(_limitations())),
            "</body></html>",
        ]
    )
    return "\n".join(sections)



def _cap_hits_by_rule(hits: list[SearchHit], max_examples_per_rule: int) -> list[SearchHit | None]:
    grouped: dict[str, list[SearchHit]] = defaultdict(list)
    for hit in hits:
        grouped[hit.rule_id].append(hit)

    capped: list[SearchHit | None] = []
    for rule_id in sorted(grouped):
        rule_hits = grouped[rule_id]
        capped.extend(rule_hits[:max_examples_per_rule])
        if len(rule_hits) > max_examples_per_rule:
            capped.append(None)
    return capped


def _html_hits_with_rule_cap(
    hits: list[SearchHit], max_examples_per_rule: int, max_report_raw_line_chars: int
) -> str:
    if not hits:
        return "<p>None</p>"
    blocks: list[str] = []
    for item in _cap_hits_by_rule(hits, max_examples_per_rule):
        if item is None:
            blocks.append("<p><em>Additional hits omitted from report. See all_hits.csv.</em></p>")
        else:
            blocks.append(_html_hit(item, max_report_raw_line_chars))
    return "\n".join(blocks)

def _text_finding_lines(hit: SearchHit, max_report_raw_line_chars: int) -> list[str]:
    return [
        f"- rule_id: {hit.rule_id}",
        f"  severity: {hit.severity}",
        f"  likely issue family: {hit.issue_category}",
        f"  component: {hit.component}",
        f"  matched_file: {hit.artifact_path}",
        f"  line_or_offset: {hit.line_number or hit.byte_offset}",
        f"  timestamp: {hit.timestamp}",
        f"  observed evidence: {_truncate_report_text(hit.raw_line, max_report_raw_line_chars)}",
        f"  context_before: {_truncate_report_text(hit.context_before, max_report_raw_line_chars)}",
        f"  context_after: {_truncate_report_text(hit.context_after, max_report_raw_line_chars)}",
        f"  KB candidate: {hit.kb_candidate_ids}",
        f"  why_this_matched: Pattern matched text '{hit.matched_text}'.",
        f"  false_positive_caution: {_hit_false_positive_caution(hit)}",
        f"  required_evidence_status: {_hit_required_evidence_status(hit)}",
    ]


def _html_hits(hits: list[SearchHit]) -> str:
    if not hits:
        return "<p>None</p>"
    return "\n".join(_html_hit(hit) for hit in hits)


def _html_hit(hit: SearchHit, max_report_raw_line_chars: int = 2_000) -> str:
    return (
        "<div class='finding'>"
        f"<p><strong>rule_id:</strong> {html.escape(hit.rule_id)}<br>"
        f"<strong>severity:</strong> {html.escape(hit.severity)}<br>"
        f"<strong>likely issue family:</strong> {html.escape(hit.issue_category)}<br>"
        f"<strong>component:</strong> {html.escape(hit.component)}<br>"
        f"<strong>matched_file:</strong> {html.escape(hit.artifact_path)}<br>"
        "<strong>line_number or byte_offset:</strong> "
        f"{html.escape(hit.line_number or hit.byte_offset)}<br>"
        f"<strong>timestamp:</strong> {html.escape(hit.timestamp)}<br>"
        f"<strong>KB candidate:</strong> {html.escape(hit.kb_candidate_ids)}<br>"
        "<strong>why_this_matched:</strong> Pattern matched text "
        f"{html.escape(hit.matched_text)}.<br>"
        "<strong>false_positive_caution:</strong> "
        f"{html.escape(_hit_false_positive_caution(hit))}<br>"
        "<strong>required_evidence_status:</strong> "
        f"{html.escape(_hit_required_evidence_status(hit))}</p>"
        f"<pre>raw_line: {html.escape(hit.raw_line)}\n"
        f"context_before: {html.escape(hit.context_before)}\n"
        f"context_after: {html.escape(hit.context_after)}</pre>"
        "</div>"
    )


def _html_findings_by_file(findings: list[FindingByFile]) -> str:
    rows = [
        "<table><tr><th>Artifact</th><th>Family</th><th>Hits</th><th>Rules</th><th>Limitations</th></tr>"
    ]
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.artifact_path)}</td>"
            f"<td>{html.escape(finding.artifact_family)}</td>"
            f"<td>{finding.hit_count}</td>"
            f"<td>{html.escape(finding.matched_rule_ids)}</td>"
            f"<td>{html.escape(finding.limitations)}</td>"
            "</tr>"
        )
    rows.append("</table>")
    return "\n".join(rows)


def _html_artifacts_not_decoded(rows: list[ArtifactCoverageRow]) -> str:
    not_decoded = [
        row for row in rows if not row.decoded_successfully and row.review_mode != "stream-scanned"
    ]
    return _html_list([_artifact_line(row).removeprefix("- ") for row in not_decoded])


def _html_section(title: str, body: str) -> str:
    return f"<section><h2>{html.escape(title)}</h2>\n{body}\n</section>"


def _html_list(items: list[str]) -> str:
    if not items:
        return "<p>None</p>"
    return "<ul>" + "".join(f"<li>{html.escape(item)}</li>" for item in items) + "</ul>"


def _artifact_line(row: ArtifactCoverageRow) -> str:
    return f"- {row.artifact_path} ({row.artifact_family}; {row.review_mode}) {row.limitations}"


def _product_detected(hits: list[SearchHit]) -> str:
    if any(hit.product == APPCONTROL_PRODUCT for hit in hits):
        return APPCONTROL_PRODUCT
    return "Unknown"


def _kb_lines(hits: list[SearchHit], kb_titles: dict[str, str]) -> list[str]:
    kb_ids = sorted(
        {
            candidate.removeprefix("KB candidate ")
            for hit in hits
            for candidate in hit.kb_candidate_ids.split(";")
            if candidate
        }
    )
    if not kb_ids:
        return ["None"]
    return [f"KB candidate {kb_id}: {kb_titles.get(kb_id, 'Unknown title')}" for kb_id in kb_ids]


def _warnings(rows: list[ArtifactCoverageRow]) -> list[str]:
    warnings = [f"{row.artifact_path}: {row.limitations}" for row in rows if row.limitations]
    return warnings or ["None"]


def _limitations() -> list[str]:
    return [
        "KB candidates require independent validation.",
        "Optional decoders, EDR rules, and Carbon Black Cloud rules are not implemented.",
    ]


def _relevant_false_positive_cautions(hits: list[SearchHit]) -> list[str]:
    if not hits:
        return ["No hits were observed; false-positive cautions are not applicable."]
    return FALSE_POSITIVE_REPORT_CAUTIONS


def _hit_false_positive_caution(hit: SearchHit) -> str:
    if hit.product == APPCONTROL_PRODUCT:
        return "Review surrounding evidence; KB labels are candidates only."
    return "Generic keyword hit; review context."


def _hit_required_evidence_status(hit: SearchHit) -> str:
    if hit.product == APPCONTROL_PRODUCT:
        return "Observed evidence present; collect missing evidence before conclusion."
    return "Not applicable for generic search."


def _required_evidence_status(rule_id: str, rule: AppControlRule | None) -> str:
    if rule_id == "GENERIC_SEARCH" or rule is None:
        return "Not applicable for generic search."
    return "Observed evidence present; missing evidence checklist remains open."


def _available_evidence(rows: list[ArtifactCoverageRow], hits: list[SearchHit]) -> set[str]:
    available = {
        row.artifact_family.lower()
        for row in rows
        if not (row.artifact_family == "agent_trace_bt9" and row.bytes_scanned == 0)
    }
    searchable_text = "\n".join(
        [row.artifact_path for row in rows]
        + [hit.raw_line for hit in hits]
        + [hit.matched_text for hit in hits]
    ).lower()
    for token in (
        "trace.bt9",
        "reporterlog",
        "reporter.log",
        "parityreporter.exe check",
        "reporterconnectivityerror",
        "services.bit9.com",
        "sqltrace",
        "cb analysis script",
        "phperrors",
        "file hash",
        "validationerror",
        "tamper",
        "serverinstall",
        "appcwebserver",
    ):
        if token == "trace.bt9" and _empty_trace_present(rows):
            continue
        if token in searchable_text:
            available.add(token)
    return available



def _empty_trace_present(rows: list[ArtifactCoverageRow]) -> bool:
    return any(
        Path(row.artifact_path).name.lower() == "trace.bt9" and row.bytes_scanned == 0
        for row in rows
    )


def _truncate_report_text(text: str, max_chars: int) -> str:
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    return text[:max_chars] + "...[truncated]"


def _evidence_item_observed(item: str, available: set[str]) -> bool:
    lookup = item.lower()
    if "trace.bt9" in lookup:
        return "agent_trace_bt9" in available or "trace.bt9" in available
    if "reporterlog" in lookup:
        return (
            "reporter_log" in available or "reporterlog" in available or "reporter.log" in available
        )
    if "sqltrace" in lookup:
        return "sql_trace" in available or "sqltrace" in available
    if "cb analysis" in lookup:
        return "cb_analysis_output" in available or "cb analysis script" in available
    return any(token in lookup or lookup in token for token in available)


def _pattern_seen_in_rows(pattern: str, rows: list[ArtifactCoverageRow]) -> bool:
    lowered_pattern = pattern.lower()
    if lowered_pattern == "ssl key pinning mismatch":
        needles = ("ssl key pinning", "mismatch")
    else:
        needles = (lowered_pattern,)
    for row in rows:
        path = Path(row.artifact_path)
        if not path.exists() or not path.is_file():
            continue
        try:
            with path.open("r", encoding=row.encoding or "utf-8", errors="ignore") as file_obj:
                for line in file_obj:
                    lowered = line.lower()
                    if all(needle in lowered for needle in needles):
                        return True
        except OSError:
            continue
    return False


def _load_kb_titles() -> dict[str, str]:
    kb_path = app_root() / "rules" / "kb_candidates.json"
    try:
        payload = json.loads(kb_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        str(item.get("kb_id")): str(item.get("title")) for item in payload.get("candidates", [])
    }
