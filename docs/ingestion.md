# Ingestion and Artifact Coverage

The current implementation adds a local-only ingestion pipeline. It recursively
walks selected input files and folders, creates a timestamped per-scan workspace,
safely extracts supported archives, classifies discovered artifacts, streams
text and binary baseline scans, and writes `artifact_coverage.csv` plus
`all_hits.csv`.

## Workspace layout

Each scan writes only under the selected output folder:

```text
output/
  scans/
    YYYYMMDD-HHMMSS/
      artifact_coverage.csv
      all_hits.csv
      findings_by_rule.csv
      findings_by_file.csv
      missing_evidence_checklist.txt
      triage_report.html
      triage_report.txt
      tdsynnex_carbon_black_log_parser.log
      extracted/
        archive-0001/
        archive-0002/
```

## Supported archive extraction

The portable app uses only Python standard-library archive support:

- `.zip` through `zipfile`
- `.tar`, `.tgz`, `.tar.gz`, `.tbz`, `.tar.bz2`, `.txz`, and `.tar.xz` through
  `tarfile`

Nested supported archives are extracted recursively until the configured archive
depth limit is reached. Archive hashes are tracked during a scan so repeated
archive content is not extracted indefinitely.

## Safety controls

Archive extraction refuses unsafe members before writing files:

- Absolute archive member paths are refused.
- Path traversal outside the workspace is refused.
- Zip symlinks are refused.
- Tar symlinks and hardlinks are refused.
- Non-regular tar members are refused.
- Per-file and total extracted-byte limits are enforced.

Refused members are not silently skipped. They are recorded in
`artifact_coverage.csv` with `review_mode` set to `skipped-by-policy` and
`decoder_status` set to `unsafe-archive-path-refused` or the relevant policy
status.

## Baseline scanning

Readable text-like artifacts are scanned line by line using streaming I/O so
large files are not loaded into memory. The scanner records line numbers, raw
matched lines, the selected text encoding, and two context lines before and
after each hit. Binary/opaque artifacts are scanned by extracting feasible
printable ASCII and UTF-16LE-like strings and recording byte offsets when
available.

The generic baseline search set is intentionally product-neutral and writes
placeholder metadata with `rule_id` set to `GENERIC_SEARCH`. Carbon Black App
Control text artifacts are also matched against the bundled deterministic JSON
rule pack in `rules/app_control_rules.json`. Matching rules populate App Control
metadata and KB candidate labels in `all_hits.csv`; KBs remain candidates only
and are not confirmed root causes. EDR, Carbon Black Cloud, and optional decoder
rules are not implemented.

## Current classification scope

Classification is intentionally shallow and deterministic. The pipeline
identifies supported Carbon Black App Control artifact families using content
markers first, then falls back to obvious file content and extension checks.
Optional decoders and final-cause confirmation are not implemented.

## Derived reports

The scan workspace includes grouped findings by rule and file, a missing evidence
checklist, and local HTML/TXT triage reports. The reports use terms such as
Observed evidence, Likely issue family, KB candidate, Missing evidence, and
Limitation. Negative searches are reported only when relevant artifacts were
actually scanned.

Unsupported or optionally decoded artifacts such as `.7z`, `.cab`, `.pcapng`,
`.evtx`, `.etl`, and `.pdf` are still listed in artifact coverage. Optional
helpers are discovered from `tools/` first and `PATH` second. Missing helpers are
recorded as `specialized-tool-unavailable` and never stop the scan; PCAP/PCAPNG
and ETL artifacts also receive binary string fallback when helper decoding is not
available. Decoded helper output is written under `decoded/` and scanned like
normal CSV/text when produced.
