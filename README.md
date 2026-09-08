# Tocsin

An evidence-based security scanner for malware, known software vulnerabilities, and operating-system security posture.

**Status: design and implementation planning. No working scanner has been released.** This repository is private during initial development; the project is intended for a future open-source release. MIT is the proposed code license, subject to dependency and distribution review before release.

## Direction

Tocsin starts as an on-demand command-line tool for macOS. Its shared core and platform adapters are designed to allow Linux and Windows support later. Those platforms are planned, not currently supported.

The first release is planned to provide:

- Selected-file malware scanning through a separately installed ClamAV engine.
- Known-vulnerability checks for supported project dependencies through OSV-Scanner.
- Homebrew inventory, initially limited verified advisory matching for curl, and explicit coverage gaps for other formulae.
- Audit history and source-linked package context from [OSS Security KB](https://github.com/travis-burmaster/oss-security-kb).
- macOS security configuration and startup-entry checks.
- Readable terminal reports and structured JSON with evidence, confidence, and incomplete-check reporting.

Tocsin will distinguish detected threats, items needing review, and unknown coverage. A missing advisory or audit is not proof that software is safe. Initial scans report findings without deleting or quarantining files. Files stay local; online dependency advisory queries are explicitly enabled and disclose that package identities may be transmitted.

## Planned interface

These commands describe the intended interface; they are not runnable yet.

```text
tocsin doctor
tocsin scan --brew --kb /path/to/oss-security-kb
tocsin scan --files /path/to/selected-folder
tocsin scan --project /path/to/project --osv-database /path/to/osv-db
tocsin scan --project /path/to/project --online
tocsin scan --posture --format json --output report.json
```

`--kb PATH` is optional for every scope. Without it, package results carry no knowledge-base context and say so. Project scans are offline by default and need a local OSV database via `--osv-database`; `--online` instead queries the OSV service and transmits package names and versions.

Exit codes: 0 means every requested check completed with no actionable findings, 1 means completed with findings, and 2 means at least one check was incomplete or failed. Packages that Tocsin cannot yet assess are listed as unassessed and do not change the exit code.

## Project documents

- [Design and acceptance criteria](docs/superpowers/specs/2026-09-08-tocsin-design.md)
- [Implementation plan](docs/superpowers/plans/2026-09-08-tocsin-implementation.md)

## Knowledge-base attribution

[OSS Security KB](https://github.com/travis-burmaster/oss-security-kb) is maintained by Travis Burmaster with LLM assistance and distributed under [CC BY 4.0](https://github.com/travis-burmaster/oss-security-kb/blob/main/LICENSE). Tocsin will preserve attribution, source references, snapshot identity, and notices for transformed extracts. KB content and separately installed scanning engines retain their respective licenses.
