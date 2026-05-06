"""Generic baseline streaming scanners for text and binary artifacts."""

from __future__ import annotations

import codecs
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from app.core.report.hits import SearchHit, make_hit
from app.core.rules.app_control import match_app_control_rules

GENERIC_SEARCH_TERMS = [
    "error",
    "failed",
    "failure",
    "timeout",
    "access denied",
    "denied",
    "blocked",
    "tamper",
    "crash",
    "assertion",
    "certificate",
    "cert",
    "ssl",
    "tls",
    "winhttp",
    "proxy",
    "dns",
    "disconnected",
    "not permitted",
    "services.bit9.com",
    "41002",
    "443",
]

TEXT_SCANNABLE_FAMILIES = {
    "server_bt9",
    "agent_trace_bt9",
    "reporter_log",
    "sql_trace",
    "api_log",
    "php_errors",
    "appcontrol_ad",
    "cb_analysis_output",
    "text_log",
    "csv",
    "json",
    "xml",
    "html",
}
BINARY_SCANNABLE_FAMILIES = {"opaque_binary", "unknown"}
_CONTEXT_LINES = 2
_CHUNK_SIZE = 1024 * 1024
_PRINTABLE_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")


@dataclass(frozen=True)
class ScanStats:
    """Scan result metadata used for artifact coverage updates."""

    review_mode: str
    lines_or_rows_scanned: int
    bytes_scanned: int
    decoded_successfully: bool
    decoder_used: str
    decoder_status: str
    encoding: str
    limitations: str = ""
    hits: list[SearchHit] = field(default_factory=list)


def scan_text_file(path: Path) -> ScanStats:
    """Stream a text-like file line by line and collect generic keyword hits."""
    candidates = _candidate_text_encodings(path)
    if not candidates:
        return ScanStats(
            review_mode="unreadable",
            lines_or_rows_scanned=0,
            bytes_scanned=_safe_size(path),
            decoded_successfully=False,
            decoder_used="text-line-scanner",
            decoder_status="unreadable",
            encoding="",
            limitations="Unable to inspect file for supported text encodings.",
        )

    last_failure: ScanStats | None = None
    for encoding in candidates:
        scan_stats = _scan_text_with_encoding(path, encoding)
        if scan_stats.decoded_successfully:
            return scan_stats
        last_failure = scan_stats
        if scan_stats.decoder_status != "decode-failed":
            return scan_stats

    return last_failure or ScanStats(
        review_mode="unreadable",
        lines_or_rows_scanned=0,
        bytes_scanned=_safe_size(path),
        decoded_successfully=False,
        decoder_used="text-line-scanner",
        decoder_status="unreadable",
        encoding="",
        limitations="Unable to decode file with supported text encodings.",
    )


def _scan_text_with_encoding(path: Path, encoding: str) -> ScanStats:
    hits: list[SearchHit] = []
    pending_hits: deque[_PendingTextHit] = deque()
    context_before: deque[str] = deque(maxlen=_CONTEXT_LINES)
    lines_scanned = 0
    bytes_scanned = _safe_size(path)

    try:
        with path.open("r", encoding=encoding, errors="strict", newline="") as text_file:
            for line_number, line in enumerate(text_file, start=1):
                lines_scanned = line_number
                raw_line = _strip_line_ending(line)
                for pending_hit in list(pending_hits):
                    if len(pending_hit.after_lines) < _CONTEXT_LINES:
                        pending_hit.after_lines.append(raw_line)

                for line_hit in _line_hits(raw_line):
                    pending_hits.append(
                        _PendingTextHit(
                            artifact_path=path,
                            line_number=line_number,
                            matched_text=line_hit["matched_text"],
                            raw_line=raw_line,
                            before_lines=list(context_before),
                            encoding=encoding,
                            rule_id=line_hit["rule_id"],
                            severity=line_hit["severity"],
                            product=line_hit["product"],
                            issue_category=line_hit["issue_category"],
                            component=line_hit["component"],
                            kb_candidate_ids=line_hit["kb_candidate_ids"],
                        )
                    )

                while pending_hits and len(pending_hits[0].after_lines) >= _CONTEXT_LINES:
                    hits.append(pending_hits.popleft().to_hit())

                context_before.append(raw_line)
    except UnicodeError as exc:
        return ScanStats(
            review_mode="unreadable",
            lines_or_rows_scanned=lines_scanned,
            bytes_scanned=bytes_scanned,
            decoded_successfully=False,
            decoder_used="text-line-scanner",
            decoder_status="decode-failed",
            encoding=encoding,
            limitations=f"Text decode failed with {encoding}: {exc}",
        )
    except OSError as exc:
        return ScanStats(
            review_mode="unreadable",
            lines_or_rows_scanned=lines_scanned,
            bytes_scanned=bytes_scanned,
            decoded_successfully=False,
            decoder_used="text-line-scanner",
            decoder_status="unreadable",
            encoding=encoding,
            limitations=f"Text scan failed: {exc}",
            hits=hits,
        )

    while pending_hits:
        hits.append(pending_hits.popleft().to_hit())

    return ScanStats(
        review_mode="stream-scanned",
        lines_or_rows_scanned=lines_scanned,
        bytes_scanned=bytes_scanned,
        decoded_successfully=True,
        decoder_used="text-line-scanner",
        decoder_status="scanned",
        encoding=encoding,
        hits=hits,
    )


def scan_binary_file(path: Path) -> ScanStats:
    """Stream a binary file and search extracted printable strings."""
    hits: list[SearchHit] = []
    fragments_scanned = 0
    bytes_scanned = 0
    carry = b""

    try:
        with path.open("rb") as binary_file:
            while chunk := binary_file.read(_CHUNK_SIZE):
                chunk_start = bytes_scanned
                bytes_scanned += len(chunk)
                search_chunk = carry + chunk
                search_start = chunk_start - len(carry)
                fragments_scanned += _scan_ascii_fragments(
                    path, search_chunk, search_start, hits, min_offset=chunk_start
                )
                fragments_scanned += _scan_utf16le_fragments(
                    path, search_chunk, search_start, hits, min_offset=chunk_start
                )
                carry = search_chunk[-256:]
    except OSError as exc:
        return ScanStats(
            review_mode="unreadable",
            lines_or_rows_scanned=0,
            bytes_scanned=bytes_scanned,
            decoded_successfully=False,
            decoder_used="binary-string-scanner",
            decoder_status="unreadable",
            encoding="binary",
            limitations=f"Binary scan failed: {exc}",
            hits=hits,
        )

    limitations = ""
    if fragments_scanned == 0:
        limitations = "No printable ASCII or UTF-16LE-like strings were found."

    return ScanStats(
        review_mode="binary-string-scanned",
        lines_or_rows_scanned=fragments_scanned,
        bytes_scanned=bytes_scanned,
        decoded_successfully=True,
        decoder_used="binary-string-scanner",
        decoder_status="scanned",
        encoding="binary",
        limitations=limitations,
        hits=hits,
    )


def should_scan_text_family(artifact_family: str) -> bool:
    """Return whether an artifact family should use the text line scanner."""
    return artifact_family in TEXT_SCANNABLE_FAMILIES


def should_scan_binary_family(artifact_family: str) -> bool:
    """Return whether an artifact family should use the binary string scanner."""
    return artifact_family in BINARY_SCANNABLE_FAMILIES


@dataclass
class _PendingTextHit:
    artifact_path: Path
    line_number: int
    matched_text: str
    raw_line: str
    before_lines: list[str]
    encoding: str
    rule_id: str = "GENERIC_SEARCH"
    severity: str = "Info"
    product: str = "Unknown"
    issue_category: str = "Generic keyword hit"
    component: str = "Unknown"
    kb_candidate_ids: str = ""
    after_lines: list[str] = field(default_factory=list)

    def to_hit(self) -> SearchHit:
        return make_hit(
            artifact_path=self.artifact_path,
            line_number=self.line_number,
            matched_text=self.matched_text,
            raw_line=self.raw_line,
            context_before="\n".join(self.before_lines),
            context_after="\n".join(self.after_lines),
            match_type="text-line",
            scanner="text-line-scanner",
            encoding=self.encoding,
            rule_id=self.rule_id,
            severity=self.severity,
            product=self.product,
            issue_category=self.issue_category,
            component=self.component,
            kb_candidate_ids=self.kb_candidate_ids,
        )


def _candidate_text_encodings(path: Path) -> list[str]:
    try:
        with path.open("rb") as binary_file:
            prefix = binary_file.read(4)
    except OSError:
        return []

    if prefix.startswith(codecs.BOM_UTF8):
        return ["utf-8-sig"]
    if prefix.startswith(codecs.BOM_UTF16_LE):
        return ["utf-16"]
    if prefix.startswith(codecs.BOM_UTF16_BE):
        return ["utf-16"]
    return ["utf-8", "cp1252", "latin-1"]


def _strip_line_ending(line: str) -> str:
    return line.rstrip("\r\n")


def _line_hits(text: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for rule_match in match_app_control_rules(text):
        rule = rule_match.rule
        hits.append(
            {
                "matched_text": rule_match.matched_text,
                "rule_id": rule.rule_id,
                "severity": rule.severity,
                "product": rule.product,
                "issue_category": rule.issue_category,
                "component": rule.component,
                "kb_candidate_ids": ";".join(
                    f"KB candidate {candidate}" for candidate in rule.kb_candidates
                ),
            }
        )
    for term in _matched_terms(text):
        hits.append(
            {
                "matched_text": term,
                "rule_id": "GENERIC_SEARCH",
                "severity": "Info",
                "product": "Unknown",
                "issue_category": "Generic keyword hit",
                "component": "Unknown",
                "kb_candidate_ids": "",
            }
        )
    return hits


def _matched_terms(text: str) -> list[str]:
    lower_text = text.lower()
    return [term for term in GENERIC_SEARCH_TERMS if term in lower_text]


def _scan_ascii_fragments(
    path: Path,
    data: bytes,
    data_start_offset: int,
    hits: list[SearchHit],
    min_offset: int,
) -> int:
    fragments = 0
    for match in _PRINTABLE_ASCII_RE.finditer(data):
        byte_offset = data_start_offset + match.start()
        if byte_offset < min_offset:
            continue
        fragment = match.group().decode("ascii", errors="ignore")
        fragments += 1
        _append_binary_hits(path, fragment, byte_offset, "ascii-string", hits)
    return fragments


def _scan_utf16le_fragments(
    path: Path,
    data: bytes,
    data_start_offset: int,
    hits: list[SearchHit],
    min_offset: int,
) -> int:
    fragments = 0
    for parity in (0, 1):
        current = bytearray()
        current_start: int | None = None
        index = parity
        while index + 1 < len(data):
            char_byte = data[index]
            null_byte = data[index + 1]
            if 0x20 <= char_byte <= 0x7E and null_byte == 0:
                if current_start is None:
                    current_start = index
                current.append(char_byte)
            else:
                if len(current) >= 4 and current_start is not None:
                    fragment = current.decode("ascii", errors="ignore")
                    byte_offset = data_start_offset + current_start
                    if byte_offset >= min_offset:
                        fragments += 1
                        _append_binary_hits(path, fragment, byte_offset, "utf-16le-string", hits)
                current = bytearray()
                current_start = None
            index += 2
        if len(current) >= 4 and current_start is not None:
            fragment = current.decode("ascii", errors="ignore")
            byte_offset = data_start_offset + current_start
            if byte_offset >= min_offset:
                fragments += 1
                _append_binary_hits(path, fragment, byte_offset, "utf-16le-string", hits)
    return fragments


def _append_binary_hits(
    path: Path,
    fragment: str,
    byte_offset: int,
    match_type: str,
    hits: list[SearchHit],
) -> None:
    for term in _matched_terms(fragment):
        hits.append(
            make_hit(
                artifact_path=path,
                byte_offset=byte_offset,
                matched_text=term,
                raw_line=fragment,
                context_before="",
                context_after="",
                match_type=match_type,
                scanner="binary-string-scanner",
                encoding="binary",
            )
        )


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0
