"""Input discovery, safe archive extraction, and artifact coverage pipeline."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import stat
import tarfile
import zipfile
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath

from app.core.classify.artifacts import ArtifactClassification, classify_file
from app.core.decode.helpers import decode_optional_artifact
from app.core.report.coverage import ArtifactCoverageRow
from app.core.report.hits import SearchHit
from app.core.scan.search import (
    ScanStats,
    scan_binary_file,
    scan_text_file,
    should_scan_binary_family,
    should_scan_text_family,
)
from app.core.util.config import ExtractionLimits

LOGGER = logging.getLogger(__name__)
ProgressCallback = Callable[[str], None]


class IngestPipeline:
    """Recursively discover inputs, safely extract archives, and record coverage."""

    def __init__(
        self,
        workspace: Path,
        limits: ExtractionLimits,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self.extracted_root = self.workspace / "extracted"
        self.decoded_root = self.workspace / "decoded"
        self.extracted_root.mkdir(parents=True, exist_ok=True)
        self.decoded_root.mkdir(parents=True, exist_ok=True)
        self.limits = limits
        self.progress_callback = progress_callback
        self.rows: list[ArtifactCoverageRow] = []
        self.hits: list[SearchHit] = []
        self.extracted_archive_hashes: set[str] = set()
        self.total_extracted_bytes = 0
        self._extract_counter = 0
        self._artifact_counter = 0

    def process_inputs(self, inputs: Iterable[Path]) -> list[ArtifactCoverageRow]:
        """Process input files and folders and return artifact coverage rows."""
        for input_path in inputs:
            resolved = input_path.expanduser().resolve()
            if resolved.is_dir():
                for file_path in self._iter_files(resolved):
                    self._process_file(
                        file_path, original_input=resolved, extracted_from=None, depth=0
                    )
            else:
                self._process_file(resolved, original_input=resolved, extracted_from=None, depth=0)
        return self.rows

    def _iter_files(self, folder: Path) -> Iterable[Path]:
        for root, dirs, files in os.walk(folder):
            dirs[:] = sorted(d for d in dirs if not Path(root, d).is_symlink())
            for file_name in sorted(files):
                file_path = Path(root, file_name)
                if file_path.is_symlink():
                    self._record_policy_row(
                        artifact_path=file_path,
                        original_input_path=folder,
                        extracted_from=None,
                        artifact_family="unknown",
                        identified_by="filesystem:symlink",
                        decoder_status="skipped-symlink-input",
                        limitations=(
                            "Input symlink was skipped to keep processing local and deterministic."
                        ),
                    )
                    continue
                yield file_path

    def _process_file(
        self,
        path: Path,
        original_input: Path,
        extracted_from: Path | None,
        depth: int,
    ) -> None:
        self._progress(f"Processing: {path}")
        if not path.exists() or not path.is_file():
            self._record_policy_row(
                artifact_path=path,
                original_input_path=original_input,
                extracted_from=extracted_from,
                artifact_family="unknown",
                identified_by="filesystem:missing-or-not-file",
                decoder_status="unreadable",
                review_mode="unreadable",
                limitations="Path does not exist or is not a regular file.",
            )
            return

        classification = classify_file(path)
        artifact_id = self._next_artifact_id()
        decoder_result = decode_optional_artifact(
            path,
            classification.artifact_family,
            self.decoded_root,
            artifact_id,
            self.extracted_root,
        )
        scan_stats = (
            decoder_result.scan_stats
            if decoder_result is not None
            else self._scan_artifact(path, classification)
        )
        self.hits.extend(scan_stats.hits)
        coverage_row = self._coverage_row(
            path=path,
            original_input=original_input,
            extracted_from=extracted_from,
            classification=classification,
            scan_stats=scan_stats,
        )
        self.rows.append(coverage_row)

        if classification.is_supported_archive and self._extract_archive(
            path, original_input, depth
        ):
            coverage_row.decoder_status = "extracted-with-limitations"
            coverage_row.limitations = (
                "Archive extracted with limitations; see artifact coverage rows."
            )

        if decoder_result is not None:
            for decoded_path in decoder_result.decoded_paths:
                self._process_file(
                    decoded_path,
                    original_input=original_input,
                    extracted_from=path,
                    depth=depth + 1,
                )

    def _scan_artifact(self, path: Path, classification: ArtifactClassification) -> ScanStats:
        try:
            if should_scan_text_family(classification.artifact_family):
                return scan_text_file(path)
            if should_scan_binary_family(classification.artifact_family):
                return scan_binary_file(path)
        except Exception as exc:  # keep one bad artifact from stopping the scan
            LOGGER.exception("Artifact scan failed: %s", path)
            return ScanStats(
                review_mode="unreadable",
                lines_or_rows_scanned=0,
                bytes_scanned=self._file_size(path),
                decoded_successfully=False,
                decoder_used="generic-scanner",
                decoder_status="scan-failed",
                encoding="",
                limitations=f"Artifact scan failed: {exc}",
            )

        return ScanStats(
            review_mode=classification.review_mode,
            lines_or_rows_scanned=0,
            bytes_scanned=self._file_size(path),
            decoded_successfully=classification.decoded_successfully,
            decoder_used=classification.decoder_used,
            decoder_status=classification.decoder_status,
            encoding="",
            limitations=classification.limitations,
        )

    def _next_artifact_id(self) -> str:
        self._artifact_counter += 1
        return f"{self._artifact_counter:06d}"

    def _extract_archive(self, archive_path: Path, original_input: Path, depth: int) -> bool:
        if depth >= self.limits.max_archive_depth:
            self._record_policy_row(
                artifact_path=archive_path,
                original_input_path=original_input,
                extracted_from=archive_path,
                artifact_family="unknown",
                identified_by="policy:max_archive_depth",
                decoder_status="skipped-by-policy",
                limitations=f"Maximum archive depth {self.limits.max_archive_depth} reached.",
            )
            return True

        archive_hash = self._sha256(archive_path)
        if archive_hash in self.extracted_archive_hashes:
            self._record_policy_row(
                artifact_path=archive_path,
                original_input_path=original_input,
                extracted_from=archive_path,
                artifact_family="unknown",
                identified_by="hash:sha256",
                decoder_status="archive-loop-detected",
                limitations="Archive hash was already extracted during this scan.",
            )
            return True
        self.extracted_archive_hashes.add(archive_hash)

        self._extract_counter += 1
        destination = self.extracted_root / f"archive-{self._extract_counter:04d}"
        destination.mkdir(parents=True, exist_ok=False)

        before_extract_rows = len(self.rows)
        try:
            if zipfile.is_zipfile(archive_path):
                extracted = self._extract_zip(archive_path, destination, original_input)
            elif tarfile.is_tarfile(archive_path):
                extracted = self._extract_tar(archive_path, destination, original_input)
            else:
                return False
        except (OSError, RuntimeError, tarfile.TarError, zipfile.BadZipFile) as exc:
            LOGGER.exception("Archive extraction failed: %s", archive_path)
            self._record_policy_row(
                artifact_path=archive_path,
                original_input_path=original_input,
                extracted_from=archive_path,
                artifact_family="unknown",
                identified_by="extract:error",
                decoder_status="decode-failed",
                review_mode="inaccessible",
                limitations=f"Archive extraction failed: {exc}",
            )
            return True

        has_limitations = len(self.rows) > before_extract_rows
        for extracted_path in extracted:
            self._process_file(
                extracted_path, original_input, extracted_from=archive_path, depth=depth + 1
            )
        return has_limitations

    def _extract_zip(
        self, archive_path: Path, destination: Path, original_input: Path
    ) -> list[Path]:
        extracted: list[Path] = []
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                target = self._safe_member_target(member.filename, destination)
                unsafe_reason = self._zip_unsafe_reason(member, target, destination)
                if unsafe_reason is not None:
                    self._record_unsafe_archive_member(
                        archive_path, member.filename, original_input, unsafe_reason
                    )
                    continue
                if self._zip_member_is_encrypted(member):
                    self._record_encrypted_zip_member(archive_path, member.filename, original_input)
                    continue
                if member.file_size > self.limits.max_single_file_bytes:
                    self._record_unsafe_archive_member(
                        archive_path,
                        member.filename,
                        original_input,
                        f"File exceeds max_single_file_bytes "
                        f"({self.limits.max_single_file_bytes}).",
                    )
                    continue
                if not self._reserve_extracted_bytes(member.file_size):
                    self._record_unsafe_archive_member(
                        archive_path,
                        member.filename,
                        original_input,
                        f"Extraction exceeds max_total_extracted_bytes "
                        f"({self.limits.max_total_extracted_bytes}).",
                    )
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with archive.open(member, "r") as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
                except RuntimeError as exc:
                    if self._is_password_required_error(exc):
                        self._record_encrypted_zip_member(
                            archive_path, member.filename, original_input
                        )
                        target.unlink(missing_ok=True)
                        continue
                    raise
                extracted.append(target)
        return extracted

    def _extract_tar(
        self, archive_path: Path, destination: Path, original_input: Path
    ) -> list[Path]:
        extracted: list[Path] = []
        with tarfile.open(archive_path) as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                target = self._safe_member_target(member.name, destination)
                unsafe_reason = self._tar_unsafe_reason(member, target, destination)
                if unsafe_reason is not None:
                    self._record_unsafe_archive_member(
                        archive_path, member.name, original_input, unsafe_reason
                    )
                    continue
                if member.size > self.limits.max_single_file_bytes:
                    self._record_unsafe_archive_member(
                        archive_path,
                        member.name,
                        original_input,
                        f"File exceeds max_single_file_bytes "
                        f"({self.limits.max_single_file_bytes}).",
                    )
                    continue
                if not self._reserve_extracted_bytes(member.size):
                    self._record_unsafe_archive_member(
                        archive_path,
                        member.name,
                        original_input,
                        f"Extraction exceeds max_total_extracted_bytes "
                        f"({self.limits.max_total_extracted_bytes}).",
                    )
                    continue
                source = archive.extractfile(member)
                if source is None:
                    self._record_unsafe_archive_member(
                        archive_path,
                        member.name,
                        original_input,
                        "Tar member is not a regular readable file.",
                    )
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                extracted.append(target)
        return extracted

    def _safe_member_target(self, member_name: str, destination: Path) -> Path | None:
        normalized = member_name.replace("\\", "/")
        pure_path = PurePosixPath(normalized)
        has_windows_drive = bool(pure_path.parts and pure_path.parts[0].endswith(":"))
        if (
            pure_path.is_absolute()
            or has_windows_drive
            or any(part == ".." for part in pure_path.parts)
        ):
            return None
        if not pure_path.parts:
            return None
        target = (destination / Path(*pure_path.parts)).resolve()
        try:
            target.relative_to(destination.resolve())
        except ValueError:
            return None
        return target

    def _zip_member_is_encrypted(self, member: zipfile.ZipInfo) -> bool:
        return bool(member.flag_bits & 0x1)

    def _is_password_required_error(self, exc: RuntimeError) -> bool:
        message = str(exc).lower()
        return "password required" in message or "encrypted" in message

    def _zip_unsafe_reason(
        self, member: zipfile.ZipInfo, target: Path | None, destination: Path
    ) -> str | None:
        if target is None:
            return "Archive member uses an absolute or path-traversal path."
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            return "Zip symlink extraction is refused."
        try:
            target.relative_to(destination.resolve())
        except ValueError:
            return "Archive member would extract outside the workspace."
        return None

    def _tar_unsafe_reason(
        self, member: tarfile.TarInfo, target: Path | None, destination: Path
    ) -> str | None:
        if target is None:
            return "Archive member uses an absolute or path-traversal path."
        if member.issym() or member.islnk():
            return "Tar symlink or hardlink extraction is refused."
        if not member.isfile():
            return "Tar member is not a regular file."
        try:
            target.relative_to(destination.resolve())
        except ValueError:
            return "Archive member would extract outside the workspace."
        return None

    def _record_encrypted_zip_member(
        self,
        archive_path: Path,
        member_name: str,
        original_input: Path,
    ) -> None:
        artifact_path = f"{archive_path}!{member_name}"
        LOGGER.warning("Encrypted ZIP member skipped: %s", artifact_path)
        self.rows.append(
            ArtifactCoverageRow(
                artifact_path=artifact_path,
                original_input_path=str(original_input),
                extracted_from=str(archive_path),
                artifact_family="unknown",
                identified_by="archive-member:zip-encrypted",
                review_mode="skipped-password-required",
                line_numbers_supported=False,
                lines_or_rows_scanned=0,
                bytes_scanned=0,
                decoded_successfully=False,
                decoder_used="zipfile",
                decoder_status="password-required",
                encoding="",
                root_cause_value="",
                related_rule_ids="",
                limitations="ZIP member is encrypted/password-protected and was not extracted.",
            )
        )

    def _record_unsafe_archive_member(
        self,
        archive_path: Path,
        member_name: str,
        original_input: Path,
        reason: str,
    ) -> None:
        LOGGER.warning(
            "Refused unsafe archive member %s in %s: %s", member_name, archive_path, reason
        )
        self.rows.append(
            ArtifactCoverageRow(
                artifact_path=f"{archive_path}!{member_name}",
                original_input_path=str(original_input),
                extracted_from=str(archive_path),
                artifact_family="unknown",
                identified_by="archive-member:safety-check",
                review_mode="skipped-by-policy",
                line_numbers_supported=False,
                lines_or_rows_scanned=0,
                bytes_scanned=0,
                decoded_successfully=False,
                decoder_used="none",
                decoder_status="unsafe-archive-path-refused",
                encoding="",
                root_cause_value="",
                related_rule_ids="",
                limitations=reason,
            )
        )

    def _record_policy_row(
        self,
        artifact_path: Path,
        original_input_path: Path,
        extracted_from: Path | None,
        artifact_family: str,
        identified_by: str,
        decoder_status: str,
        limitations: str,
        review_mode: str = "skipped-by-policy",
    ) -> None:
        self.rows.append(
            ArtifactCoverageRow(
                artifact_path=str(artifact_path),
                original_input_path=str(original_input_path),
                extracted_from=str(extracted_from) if extracted_from else "",
                artifact_family=artifact_family,
                identified_by=identified_by,
                review_mode=review_mode,
                line_numbers_supported=False,
                lines_or_rows_scanned=0,
                bytes_scanned=0,
                decoded_successfully=False,
                decoder_used="none",
                decoder_status=decoder_status,
                encoding="",
                root_cause_value="",
                related_rule_ids="",
                limitations=limitations,
            )
        )

    def _coverage_row(
        self,
        path: Path,
        original_input: Path,
        extracted_from: Path | None,
        classification: ArtifactClassification,
        scan_stats: ScanStats,
    ) -> ArtifactCoverageRow:
        return ArtifactCoverageRow(
            artifact_path=str(path),
            original_input_path=str(original_input),
            extracted_from=str(extracted_from) if extracted_from else "",
            artifact_family=classification.artifact_family,
            identified_by=classification.identified_by,
            review_mode=scan_stats.review_mode,
            line_numbers_supported=classification.line_numbers_supported,
            lines_or_rows_scanned=scan_stats.lines_or_rows_scanned,
            bytes_scanned=scan_stats.bytes_scanned,
            decoded_successfully=scan_stats.decoded_successfully,
            decoder_used=scan_stats.decoder_used,
            decoder_status=scan_stats.decoder_status,
            encoding=scan_stats.encoding,
            root_cause_value="",
            related_rule_ids="",
            limitations=scan_stats.limitations,
        )

    def _reserve_extracted_bytes(self, byte_count: int) -> bool:
        if self.total_extracted_bytes + byte_count > self.limits.max_total_extracted_bytes:
            return False
        self.total_extracted_bytes += byte_count
        return True

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as file_obj:
            for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _file_size(self, path: Path) -> int:
        try:
            return path.stat().st_size
        except OSError:
            return 0

    def _progress(self, message: str) -> None:
        LOGGER.info(message)
        if self.progress_callback is not None:
            self.progress_callback(message)
