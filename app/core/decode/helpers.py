"""Optional portable decoder helpers with graceful fallback behavior."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

from app.core.scan.search import ScanStats, scan_binary_file
from app.core.util.paths import app_root

ETL_LIMITATION = (
    "The ETL was not fully decoded. Only metadata, converted output if available, and "
    "string-searchable content were reviewed."
)

PCAP_FIELDS = [
    "frame.number",
    "frame.time",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.analysis.retransmission",
]


@dataclass(frozen=True)
class DecoderResult:
    """Result from an optional decoder attempt."""

    scan_stats: ScanStats
    decoded_paths: list[Path] = field(default_factory=list)


def find_tshark() -> Path | None:
    """Find tshark in portable tools first, then PATH."""
    return _find_tool([app_root() / "tools" / "tshark" / "tshark.exe"], ["tshark", "tshark.exe"])


def find_7zip() -> Path | None:
    """Find 7-Zip in portable tools first, then PATH."""
    return _find_tool(
        [app_root() / "tools" / "7zip" / "7z.exe", app_root() / "tools" / "7zip" / "7zz.exe"],
        ["7z", "7z.exe", "7zz", "7zz.exe"],
    )


def find_expand() -> Path | None:
    """Find Windows expand.exe if available."""
    return _find_tool([], ["expand.exe", "expand"])


def find_wevtutil() -> Path | None:
    """Find Windows wevtutil.exe if available."""
    return _find_tool([], ["wevtutil.exe", "wevtutil"])


def find_tracerpt() -> Path | None:
    """Find Windows tracerpt.exe if available."""
    return _find_tool([], ["tracerpt.exe", "tracerpt"])


def decode_optional_artifact(
    path: Path,
    artifact_family: str,
    decoded_root: Path,
    artifact_id: str,
    extracted_root: Path,
) -> DecoderResult | None:
    """Attempt optional decoding for specialized artifacts without making it required."""
    decoded_root.mkdir(parents=True, exist_ok=True)
    if artifact_family in {"pcap", "pcapng"}:
        return _decode_pcap(path, decoded_root, artifact_id)
    if artifact_family == "seven_zip":
        return _decode_7z(path, extracted_root, artifact_id)
    if artifact_family == "cab":
        return _decode_cab(path, extracted_root, artifact_id)
    if artifact_family == "evtx":
        return _decode_evtx(path, decoded_root, artifact_id)
    if artifact_family == "etl":
        return _decode_etl(path, decoded_root, artifact_id)
    if artifact_family in {"pdf", "standard_report_pdf"}:
        return _decode_pdf(path, decoded_root, artifact_id)
    return None


def _decode_pcap(path: Path, decoded_root: Path, artifact_id: str) -> DecoderResult:
    tshark = find_tshark()
    if tshark is None:
        fallback = scan_binary_file(path)
        return DecoderResult(
            _replace_stats(
                fallback,
                decoder_used="tshark",
                decoder_status="specialized-tool-unavailable",
                limitations=(
                    "tshark was not found in tools/tshark or PATH; binary string fallback used."
                ),
            )
        )

    output_path = decoded_root / f"pcap_{artifact_id}.csv"
    command = [
        str(tshark),
        "-r",
        str(path),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
    ]
    for pcap_field in PCAP_FIELDS:
        command.extend(["-e", pcap_field])
    result = _run_tool(command)
    if result.returncode != 0:
        fallback = scan_binary_file(path)
        return DecoderResult(
            _replace_stats(
                fallback,
                decoder_used="tshark",
                decoder_status="decode-failed",
                limitations=f"tshark exited with {result.returncode}; binary string fallback used.",
            )
        )
    output_path.write_text(result.stdout, encoding="utf-8")
    return DecoderResult(
        _metadata_stats(path, decoder_used="tshark", decoder_status="decoded"), [output_path]
    )


def _decode_7z(path: Path, extracted_root: Path, artifact_id: str) -> DecoderResult:
    seven_zip = find_7zip()
    if seven_zip is None:
        return DecoderResult(
            _metadata_stats(
                path,
                decoder_used="7zip",
                decoder_status="specialized-tool-unavailable",
                limitations="7-Zip was not found in tools/7zip or PATH.",
            )
        )

    destination = extracted_root / f"7z_{artifact_id}"
    destination.mkdir(parents=True, exist_ok=True)
    list_result = _run_tool([str(seven_zip), "l", "-slt", str(path)])
    if list_result.returncode != 0:
        return DecoderResult(
            _metadata_stats(
                path,
                decoder_used="7zip",
                decoder_status="decode-failed",
                limitations=f"7-Zip listing failed with exit code {list_result.returncode}.",
            )
        )
    unsafe = _unsafe_7z_paths(list_result.stdout)
    if unsafe:
        return DecoderResult(
            _metadata_stats(
                path,
                decoder_used="7zip",
                decoder_status="skipped-by-policy",
                limitations=f"7-Zip archive contains unsafe member path: {unsafe[0]}",
            )
        )
    extract_result = _run_tool([str(seven_zip), "x", "-y", f"-o{destination}", str(path)])
    if extract_result.returncode != 0:
        return DecoderResult(
            _metadata_stats(
                path,
                decoder_used="7zip",
                decoder_status="decode-failed",
                limitations=f"7-Zip extraction failed with exit code {extract_result.returncode}.",
            )
        )
    return DecoderResult(
        _metadata_stats(path, decoder_used="7zip", decoder_status="decoded"),
        _iter_regular_files(destination),
    )


def _decode_cab(path: Path, extracted_root: Path, artifact_id: str) -> DecoderResult:
    expand = find_expand()
    if expand is None:
        return DecoderResult(
            _metadata_stats(
                path,
                decoder_used="expand.exe",
                decoder_status="specialized-tool-unavailable",
                limitations="expand.exe was not found in PATH.",
            )
        )
    destination = extracted_root / f"cab_{artifact_id}"
    destination.mkdir(parents=True, exist_ok=True)
    result = _run_tool([str(expand), "-F:*", str(path), str(destination)])
    if result.returncode != 0:
        return DecoderResult(
            _metadata_stats(
                path,
                decoder_used="expand.exe",
                decoder_status="decode-failed",
                limitations=f"expand.exe failed with exit code {result.returncode}.",
            )
        )
    return DecoderResult(
        _metadata_stats(path, decoder_used="expand.exe", decoder_status="decoded"),
        _iter_regular_files(destination),
    )


def _decode_evtx(path: Path, decoded_root: Path, artifact_id: str) -> DecoderResult:
    wevtutil = find_wevtutil()
    if wevtutil is None:
        return DecoderResult(
            _metadata_stats(
                path,
                decoder_used="wevtutil.exe",
                decoder_status="specialized-tool-unavailable",
                limitations="wevtutil.exe was not found in PATH.",
            )
        )
    output_path = decoded_root / f"evtx_{artifact_id}.xml"
    result = _run_tool([str(wevtutil), "qe", str(path), "/lf:true", "/f:xml"])
    if result.returncode != 0:
        return DecoderResult(
            _metadata_stats(
                path,
                decoder_used="wevtutil.exe",
                decoder_status="decode-failed",
                limitations=f"wevtutil.exe failed with exit code {result.returncode}.",
            )
        )
    output_path.write_text(result.stdout, encoding="utf-8")
    return DecoderResult(
        _metadata_stats(path, decoder_used="wevtutil.exe", decoder_status="decoded"),
        [output_path],
    )


def _decode_etl(path: Path, decoded_root: Path, artifact_id: str) -> DecoderResult:
    tracerpt = find_tracerpt()
    if tracerpt is None:
        fallback = scan_binary_file(path)
        return DecoderResult(
            _replace_stats(
                fallback,
                decoder_used="tracerpt.exe",
                decoder_status="specialized-tool-unavailable",
                limitations=ETL_LIMITATION,
            )
        )
    output_path = decoded_root / f"etl_{artifact_id}.csv"
    result = _run_tool([str(tracerpt), str(path), "-o", str(output_path), "-of", "CSV"])
    if result.returncode != 0 or not output_path.exists():
        fallback = scan_binary_file(path)
        return DecoderResult(
            _replace_stats(
                fallback,
                decoder_used="tracerpt.exe",
                decoder_status="decode-failed",
                limitations=ETL_LIMITATION,
            )
        )
    return DecoderResult(
        _metadata_stats(
            path,
            decoder_used="tracerpt.exe",
            decoder_status="decoded-with-limitation",
            limitations=ETL_LIMITATION,
        ),
        [output_path],
    )


def _decode_pdf(path: Path, decoded_root: Path, artifact_id: str) -> DecoderResult:
    output_path = decoded_root / f"pdf_{artifact_id}.txt"
    if importlib.util.find_spec("pypdf") is not None:
        try:
            from pypdf import PdfReader  # type: ignore[import-not-found]

            reader = PdfReader(str(path))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            output_path.write_text(text, encoding="utf-8")
            return DecoderResult(
                _metadata_stats(path, decoder_used="pypdf", decoder_status="decoded"), [output_path]
            )
        except Exception as exc:  # PDF libraries raise broad parse exceptions
            return DecoderResult(
                _metadata_stats(
                    path,
                    decoder_used="pypdf",
                    decoder_status="decode-failed",
                    limitations=f"PDF text extraction failed; OCR is not implemented: {exc}",
                )
            )
    if importlib.util.find_spec("PyPDF2") is not None:
        try:
            from PyPDF2 import PdfReader  # type: ignore[import-not-found]

            reader = PdfReader(str(path))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            output_path.write_text(text, encoding="utf-8")
            return DecoderResult(
                _metadata_stats(path, decoder_used="PyPDF2", decoder_status="decoded"),
                [output_path],
            )
        except Exception as exc:
            return DecoderResult(
                _metadata_stats(
                    path,
                    decoder_used="PyPDF2",
                    decoder_status="decode-failed",
                    limitations=f"PDF text extraction failed; OCR is not implemented: {exc}",
                )
            )
    return DecoderResult(
        _metadata_stats(
            path,
            decoder_used="pdf-basic",
            decoder_status="specialized-tool-unavailable",
            limitations=(
                "PDF text extraction dependency unavailable; metadata-only review. "
                "OCR is not implemented."
            ),
        )
    )


def _find_tool(portable_candidates: list[Path], path_names: list[str]) -> Path | None:
    for candidate in portable_candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    for name in path_names:
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def _run_tool(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, check=False, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(command, returncode=1, stdout="", stderr=str(exc))


def _unsafe_7z_paths(listing: str) -> list[str]:
    unsafe: list[str] = []
    for line in listing.splitlines():
        if not line.startswith("Path = "):
            continue
        member = line.removeprefix("Path = ").strip()
        if not member or member.endswith(":"):
            continue
        normalized = member.replace("\\", "/")
        pure = PureWindowsPath(member)
        parts = normalized.split("/")
        if pure.is_absolute() or any(part == ".." for part in parts):
            unsafe.append(member)
    return unsafe


def _iter_regular_files(folder: Path) -> list[Path]:
    return sorted(path for path in folder.rglob("*") if path.is_file() and not path.is_symlink())


def _metadata_stats(
    path: Path,
    *,
    decoder_used: str,
    decoder_status: str,
    limitations: str = "",
) -> ScanStats:
    return ScanStats(
        review_mode="metadata-only"
        if decoder_status not in {"specialized-tool-unavailable", "decode-failed"}
        else "specialized-tool-unavailable",
        lines_or_rows_scanned=0,
        bytes_scanned=_safe_size(path),
        decoded_successfully=decoder_status in {"decoded", "decoded-with-limitation"},
        decoder_used=decoder_used,
        decoder_status=decoder_status,
        encoding="",
        limitations=limitations,
    )


def _replace_stats(
    stats: ScanStats,
    *,
    decoder_used: str,
    decoder_status: str,
    limitations: str,
) -> ScanStats:
    return ScanStats(
        review_mode=stats.review_mode,
        lines_or_rows_scanned=stats.lines_or_rows_scanned,
        bytes_scanned=stats.bytes_scanned,
        decoded_successfully=stats.decoded_successfully,
        decoder_used=decoder_used,
        decoder_status=decoder_status,
        encoding=stats.encoding,
        limitations=limitations,
        hits=stats.hits,
    )


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0
