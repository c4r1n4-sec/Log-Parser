"""Lightweight artifact classification for coverage reporting."""

from __future__ import annotations

import json
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_ARCHIVE_FAMILIES = {"zip", "tar"}
UNSUPPORTED_ARCHIVE_SUFFIXES = {
    ".7z": "seven_zip",
    ".cab": "cab",
}
TEXT_SUFFIXES = {".log", ".txt", ".out", ".err", ".trace"}
CSV_SUFFIXES = {".csv"}
JSON_SUFFIXES = {".json"}
XML_SUFFIXES = {".xml"}
HTML_SUFFIXES = {".html", ".htm"}
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff"}
SPECIALIZED_SUFFIXES = {
    ".pml": "procmon_pml",
    ".pdf": "pdf",
    ".pcap": "pcap",
    ".pcapng": "pcapng",
    ".evtx": "evtx",
    ".etl": "etl",
    ".dmp": "memory_dump",
}
TAR_SUFFIXES = (".tar", ".tgz", ".tar.gz", ".tbz", ".tar.bz2", ".txz", ".tar.xz")

APPCONTROL_STRONG_MARKERS = {
    "ServerLog",
    "trace.bt9",
    "ReporterService",
    "SQLTrace",
    "PHPErrors",
    "AppControlAD",
    "CB Analysis Script",
}

APPCONTROL_CONTENT_MARKERS = {
    "server_bt9": (
        "ServerLog",
        "ParseMessageHeader",
        "ReportEventList",
        "HostStorage",
        "request started",
        "Carbon Black App Control",
    ),
    "agent_trace_bt9": (
        "trace.bt9",
        "Server Communication",
        "GetWinHttpError",
        "GetSslError",
        "WaitForResponse",
        "Connection:",
        "Session:",
    ),
    "reporter_log": (
        "ReporterService",
        "ParityReporter",
        "AntibodyMetadataLookup",
        "DatabaseConnectionWrapper",
        "WSE2127",
        "WSE511",
        "ReporterConnectivityError",
        "Carbon Black File Reputation",
    ),
    "sql_trace": ("SQLTrace", "Duration", "CPU", "Reads", "exec", "Timeout", "SQL"),
    "api_log": ("API", "request", "response", "http"),
    "php_errors": ("PHP", "PHPErrors", "FastCGI", "Database timeout expired"),
    "appcontrol_ad": (
        "AppControlAD",
        "ADHelper",
        "LDAP",
        "AD query",
        "MapUsersToHostgroupUsingScript",
    ),
    "cb_analysis_output": (
        "CB Analysis Script",
        "App Control Server",
        "Schema",
        "Active Hosts",
        "SQL Server",
        "SOS_WORK_DISPATCHER",
        "MaxDOP",
        "AppCWebServer",
    ),
}


@dataclass(frozen=True)
class ArtifactClassification:
    """Classification result used by ingestion and coverage reporting."""

    artifact_family: str
    identified_by: str
    review_mode: str
    line_numbers_supported: bool
    decoded_successfully: bool
    decoder_used: str
    decoder_status: str
    limitations: str

    @property
    def is_supported_archive(self) -> bool:
        return self.artifact_family in SUPPORTED_ARCHIVE_FAMILIES


def classify_file(path: Path) -> ArtifactClassification:
    """Classify an artifact by content/probe first, then extension fallback."""
    suffix = path.suffix.lower()
    lower_name = path.name.lower()


    if lower_name == "trace.bt9":
        return _classification(
            "agent_trace_bt9", "name:trace.bt9", "stream-scanned", True, "pending-scan"
        )
    if lower_name == "serverlog.bt9":
        return _classification(
            "server_bt9", "name:ServerLog.bt9", "stream-scanned", True, "pending-scan"
        )

    if zipfile.is_zipfile(path):
        return _classification("zip", "content:zipfile", "metadata-only", False, "archive-detected")
    if _looks_like_tar(path):
        return _classification("tar", "content:tarfile", "metadata-only", False, "archive-detected")

    sample = _read_sample(path)
    if sample is None:
        return _classification("unknown", "probe:unreadable", "unreadable", False, "unreadable")

    app_control_family = _classify_app_control_content(sample)
    if app_control_family is not None:
        return _classification(
            app_control_family,
            "content:app-control-marker",
            "stream-scanned",
            True,
            "pending-scan",
        )

    stripped = sample.lstrip()
    if _looks_like_json(stripped):
        return _classification("json", "content:json", "stream-scanned", True, "pending-scan")
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<Event"):
        return _classification("xml", "content:xml", "stream-scanned", True, "pending-scan")
    if b"<html" in stripped[:512].lower() or b"<!doctype html" in stripped[:512].lower():
        return _classification("html", "content:html", "stream-scanned", True, "pending-scan")

    suffix_family = _classify_by_suffix(lower_name, suffix)
    if suffix_family is not None:
        return suffix_family

    if _is_probably_text(sample):
        return _classification("text_log", "content:text", "stream-scanned", True, "pending-scan")

    return _classification(
        "opaque_binary", "fallback:binary", "binary-string-scanned", False, "pending-scan"
    )


def _classification(
    family: str,
    identified_by: str,
    review_mode: str,
    line_numbers_supported: bool,
    decoder_status: str,
    *,
    decoded_successfully: bool = False,
    decoder_used: str = "none",
    limitations: str = "",
) -> ArtifactClassification:
    return ArtifactClassification(
        artifact_family=family,
        identified_by=identified_by,
        review_mode=review_mode,
        line_numbers_supported=line_numbers_supported,
        decoded_successfully=decoded_successfully,
        decoder_used=decoder_used,
        decoder_status=decoder_status,
        limitations=limitations,
    )


def _looks_like_tar(path: Path) -> bool:
    try:
        return tarfile.is_tarfile(path)
    except OSError:
        return False


def _read_sample(path: Path, size: int = 4096) -> bytes | None:
    try:
        with path.open("rb") as file_obj:
            return file_obj.read(size)
    except OSError:
        return None


def _classify_app_control_content(sample: bytes) -> str | None:
    if _has_unmarked_binary_nulls(sample):
        return None

    text = _decode_marker_sample(sample)
    if not text:
        return None

    lowered = text.lower()
    best_family = None
    best_count = 0
    for family, markers in APPCONTROL_CONTENT_MARKERS.items():
        count = sum(1 for marker in markers if marker.lower() in lowered)
        if count > best_count:
            best_family = family
            best_count = count

    if best_count == 0:
        return None
    if best_count >= 2:
        return best_family

    for marker in APPCONTROL_STRONG_MARKERS:
        if marker.lower() in lowered:
            return best_family
    return None


def _has_unmarked_binary_nulls(sample: bytes) -> bool:
    return b"\x00" in sample and not sample.startswith((b"\xff\xfe", b"\xfe\xff"))


def _decode_marker_sample(sample: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-16", "utf-8", "cp1252", "latin-1"):
        try:
            return sample.decode(encoding)
        except UnicodeError:
            continue
    return ""


def _looks_like_json(sample: bytes) -> bool:
    if not sample.startswith((b"{", b"[")):
        return False
    try:
        json.loads(sample.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    return True


def _classify_by_suffix(lower_name: str, suffix: str) -> ArtifactClassification | None:
    if suffix == ".zip":
        return _classification(
            "zip", "extension:.zip", "metadata-only", False, "invalid-or-unreadable-archive"
        )
    if lower_name.endswith(TAR_SUFFIXES):
        return _classification(
            "tar", "extension:tar", "metadata-only", False, "invalid-or-unreadable-archive"
        )
    if suffix in UNSUPPORTED_ARCHIVE_SUFFIXES:
        family = UNSUPPORTED_ARCHIVE_SUFFIXES[suffix]
        return _classification(
            family,
            f"extension:{suffix}",
            "specialized-tool-unavailable",
            False,
            "specialized-tool-unavailable",
            limitations=(
                "Archive type requires a specialized decoder not bundled with this portable app."
            ),
        )
    if suffix == ".pdf" and "standard" in lower_name and "report" in lower_name:
        return _classification(
            "standard_report_pdf",
            "extension:.pdf:name:standard-report",
            "specialized-tool-unavailable",
            False,
            "specialized-tool-unavailable",
            limitations="Standard report PDF decoding is not implemented in this skeleton.",
        )
    if suffix in SPECIALIZED_SUFFIXES:
        family = SPECIALIZED_SUFFIXES[suffix]
        return _classification(
            family,
            f"extension:{suffix}",
            "specialized-tool-unavailable",
            False,
            "specialized-tool-unavailable",
            limitations="Optional decoder is not implemented in this skeleton.",
        )
    if suffix in TEXT_SUFFIXES:
        return _classification(
            "text_log", f"extension:{suffix}", "stream-scanned", True, "pending-scan"
        )
    if suffix in CSV_SUFFIXES:
        return _classification("csv", f"extension:{suffix}", "stream-scanned", True, "pending-scan")
    if suffix in JSON_SUFFIXES:
        return _classification(
            "json", f"extension:{suffix}", "stream-scanned", True, "pending-scan"
        )
    if suffix in XML_SUFFIXES:
        return _classification("xml", f"extension:{suffix}", "stream-scanned", True, "pending-scan")
    if suffix in HTML_SUFFIXES:
        return _classification(
            "html", f"extension:{suffix}", "stream-scanned", True, "pending-scan"
        )
    if suffix in IMAGE_SUFFIXES:
        return _classification(
            "image_metadata_only", f"extension:{suffix}", "metadata-only", False, "metadata-only"
        )
    return None


def _is_probably_text(sample: bytes) -> bool:
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True
