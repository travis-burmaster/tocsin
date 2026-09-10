# Tocsin

An evidence-based security scanner for malware, known software vulnerabilities, and operating-system security posture.

**Status: implemented, not released.** The CLI, all four scan scopes (`--brew`, `--files`, `--project`, `--posture`), and `doctor` work end to end on macOS and are covered by an automated test suite. The project is intended for open-source release; no PyPI package name is currently reserved for it. Before that release: the ClamAV file-scanning adapter has been live-verified against a real ClamAV 1.5.4 engine on one macOS host (EICAR detection, an encrypted-archive skip, and the oversized-file alert string all confirmed -- see `docs/evidence/validation.md`), but only that one engine version and host, not a matrix of versions or platforms, and Intel Mac coverage is untested. The code is licensed under the MIT License (see `LICENSE`); third-party data carried in the repository is listed with its own terms in `THIRD_PARTY_NOTICES.md`.

## Direction

Tocsin is an on-demand command-line tool, currently macOS only. Its shared core and platform adapters are designed to allow Linux and Windows support later, but those platforms are not implemented -- every scan scope reports itself explicitly unsupported there, never silently skipped. See `docs/coverage.md` for the full platform/engine coverage matrix.

Implemented today:

- Selected-file malware scanning through a separately installed ClamAV engine (`--files`).
- Known-vulnerability checks for project dependencies through OSV-Scanner, offline or online (`--project`).
- Homebrew inventory (`--brew`), with reviewed advisory matching for curl and explicit coverage gaps (`unassessed`) for every other formula.
- Audit history and source-linked package context from the [OSS Security KB](https://github.com/travis-burmaster/oss-security-kb) (`--kb`, optional for every scope).
- macOS security posture and startup-entry review (`--posture`).
- Readable terminal reports and structured JSON, both carrying evidence, confidence, and explicit incomplete-check reporting.

Tocsin distinguishes detected threats, items needing review, and unknown coverage. A missing advisory or audit is never treated as proof that software is safe. Scans never delete, quarantine, or otherwise modify files. Everything is local by default; `--online` for `--project` is the one operation that transmits data (package names and versions, to the OSV advisory service) and is off unless explicitly requested.

## Interface

This is the actual output of `tocsin --help`, `tocsin scan --help`, and `tocsin doctor --help` as of this release.

```text
$ tocsin --help
usage: tocsin [-h] {doctor,scan} ...

Evidence-based security scanner for malware, known software vulnerabilities,
and operating-system security posture.

positional arguments:
  {doctor,scan}
    doctor       Report host platform, Python version, and engine
                 availability.
    scan         Run one or more scan scopes.

options:
  -h, --help     show this help message and exit
```

```text
$ tocsin scan --help
usage: tocsin scan [-h] [--brew] [--files PATH] [--project PATH] [--posture]
                   [--kb PATH] [--online] [--osv-database PATH]
                   [--format {text,json}] [--output PATH] [--overwrite]

options:
  -h, --help            show this help message and exit
  --brew                Inventory Homebrew packages and posture.
  --files PATH          Scan selected files or a selected folder.
  --project PATH        Check project dependencies for known vulnerabilities.
  --posture             Check macOS security configuration and startup
                        entries.
  --kb PATH             Optional local knowledge-base checkout for package
                        context.
  --online              Allow online advisory lookups. Package names and
                        versions may be transmitted to advisory services.
  --osv-database PATH   Offline alternative to --online for --project: a local
                        directory already populated as OSV-Scanner's
                        OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY layout
                        (<PATH>/osv-scalibr/<Ecosystem>/all.zip). Without
                        --online, --project requires this.
  --format {text,json}  Report format (default: text).
  --output PATH         Write the report to PATH instead of stdout.
  --overwrite           Allow replacing an existing --output file.

Privacy:
  By default, every scan operation is local: no data leaves this
  machine. The one exception is --online, which transmits package
  names and versions to the OSV advisory service for the --project
  scope. File contents and reports are never uploaded by Tocsin.
  Reports written with --output are created with file mode 0600;
  stdout output is left to the terminal.
```

```text
$ tocsin doctor --help
usage: tocsin doctor [-h] [--kb PATH]

options:
  -h, --help  show this help message and exit
  --kb PATH   Report readability of a local knowledge-base checkout.
```

Example invocations:

```text
tocsin doctor
tocsin doctor --kb /path/to/oss-security-kb
tocsin scan --brew --kb /path/to/oss-security-kb
tocsin scan --files /path/to/selected-folder
tocsin scan --project /path/to/project --osv-database /path/to/osv-db
tocsin scan --project /path/to/project --online
tocsin scan --posture --format json --output report.json
```

`--kb PATH` is optional for every scope. Without it, package-bearing checks record KB context as `unavailable` and never report a clean KB verdict. Project scans are offline by default and need a local OSV database via `--osv-database`; `--online` instead queries the OSV service directly. See `docs/development.md` for installing the external engines (`clamscan`, `osv-scanner`, `brew`) Tocsin drives but never installs itself, and for populating the OSV offline database.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every requested check completed, with no `detected`/`needs-review` findings. |
| 1 | Every requested check completed, with at least one `detected` or `needs-review` finding. |
| 2 | At least one check was incomplete (`partial`, `unavailable`, `error`, or carrying an `error`/`skipped` finding) -- regardless of findings elsewhere. Also covers a cancelled scan (Ctrl-C). |

Packages or settings Tocsin has no reviewed verdict for are reported `unassessed` -- a coverage gap, visible in the findings list and in `metadata['coverage']` -- and never by themselves change the exit code.

## Sample reports

`docs/samples/report-sample.txt` and `docs/samples/report-sample.json` are full sample reports generated entirely from fixture data (no real engine invoked, no real host scanned) -- see `docs/samples/README.md` for exactly how. A short excerpt of each:

Text (`docs/samples/report-sample.txt`):

```text
== brew [complete] ==
  - [detected] curl 8.0.0 (severity=High, confidence=high)
      action: upgrade curl to 8.4.0 or later
      evidence: CURL-CVE-2023-38545
      evidence: CVE-2023-38545
      evidence: range: >=7.69.0 <8.4.0
      evidence: https://curl.se/docs/CVE-2023-38545.json
      evidence: https://curl.se/docs/CVE-2023-38545.html
  - [unassessed] openssl@3 3.6.2 (severity=unknown, confidence=high)
      action: no reviewed advisory adapter for this formula
      evidence: https://github.com/travis-burmaster/oss-security-kb/blob/main/wiki/homebrew/openssl@3.md
  coverage: assessed=1 unassessed=1, kb_commit=none
```

JSON (`docs/samples/report-sample.json`):

```json
{
  "schema_version": "1",
  "generated_at": "2026-01-01T00:00:00Z",
  "host": { "platform": "Darwin", "architecture": "arm64" },
  "requested_scopes": ["brew", "files", "project"],
  "results": [
    {
      "name": "files",
      "completion": "complete",
      "findings": [
        {
          "category": "file",
          "subject": "/Users/example/selected-files/installer.pkg",
          "status": "detected",
          "severity": "unknown",
          "confidence": "high",
          "evidence": ["Eicar-Signature"],
          "action": "quarantine or delete only after manual confirmation; Tocsin does not modify files",
          "observed_at": "2026-01-01T00:00:00Z"
        }
      ],
      "errors": [],
      "metadata": { "coverage": { "assessed": 1, "unassessed": 0 } }
    }
  ]
}
```

## Project documents

- [Design and acceptance criteria](docs/superpowers/specs/2026-09-08-tocsin-design.md)
- [Implementation plan](docs/superpowers/plans/2026-09-08-tocsin-implementation.md)
- [Development setup and verification](docs/development.md)
- [Coverage matrix](docs/coverage.md)
- [Validation: verified live vs. fixture-only](docs/evidence/validation.md)

## Knowledge-base attribution

[OSS Security KB](https://github.com/travis-burmaster/oss-security-kb) is maintained by Travis Burmaster with LLM assistance and distributed under [CC BY 4.0](https://github.com/travis-burmaster/oss-security-kb/blob/main/LICENSE). Tocsin preserves attribution, source references, snapshot identity, and notices for transformed extracts. KB content and separately installed scanning engines retain their respective licenses.
