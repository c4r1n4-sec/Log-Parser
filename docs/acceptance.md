# Acceptance Checklist

Use this checklist for release validation of the portable package.

- [ ] Runs offline.
- [ ] Runs without install.
- [ ] Runs without administrator rights.
- [ ] Runs without Python installed on the target engineer machine after packaging.
- [ ] Does not make outbound network calls.
- [ ] Does not send telemetry.
- [ ] Scans individual files.
- [ ] Scans folders.
- [ ] Scans ZIP bundles, including nested ZIPs.
- [ ] Produces `artifact_coverage.csv`.
- [ ] Produces `all_hits.csv`.
- [ ] Produces `findings_by_rule.csv`.
- [ ] Produces `findings_by_file.csv`.
- [ ] Produces `missing_evidence_checklist.txt`.
- [ ] Produces `triage_report.html`.
- [ ] Produces `triage_report.txt`.
- [ ] Does not crash when optional helpers are missing.
- [ ] Records missing optional helpers in artifact coverage limitations/status.
- [ ] Does not claim unsupported root cause.
- [ ] Labels KBs as candidates only.
- [ ] Does not perform remediation.
- [ ] Does not execute SQL.
- [ ] Does not perform OCR.
- [ ] Does not include EDR/CBC rules in v1.0.
- [ ] Does not create an installer, MSI, or `setup.exe`.

## Synthetic bundle acceptance

A synthetic App Control bundle should include:

- ReporterLog with `Execution Timeout Expired`.
- `trace.bt9` with `GetSslError[16]`.
- ServerLog with `AppCWebServer` evidence.
- Generic binary file with printable strings.
- Nested ZIP content.

The scan should produce all required reports, App Control rule hits, missing
evidence prompts, and valid negative searches where relevant artifacts were
actually scanned.
