# Tocsin — initial design

Status: planning baseline. Command-line first scope and the Tocsin name selected by the owner; macOS first, Linux and Windows planned.

## Outcome

An open-source, on-demand command-line application that scans selected files for malware, identifies known vulnerabilities in supported installed packages and project dependencies, and enriches results with OSS Security KB audit context. Produce text and JSON reports with evidence, coverage, and actionable suggestions. It does not claim to discover new vulnerabilities or provide continuous protection.

## Source inspection

Inspected https://github.com/travis-burmaster/oss-security-kb at commit `30f536b7a81a681c340b2a37e044089623741ccb` on 2026-09-08, including SCHEMA.md, METHODOLOGY.md, CLAUDE.md, and the curl and openssl@3 Homebrew pages. The repository holds Markdown knowledge pages, not an executable scanner or complete affected-version database. Its schema distinguishes baseline stubs, advisory mapping, audit ingestion, and needs-rereview. The OpenSSL page is a baseline stub. The curl page includes backend-specific applicability qualifications. Fixed-version columns alone cannot establish affected ranges.

Build in a separate project. Consume local KB snapshots without modifying the source repository. Preserve CC BY 4.0 attribution, source links, modification notices for transformed extracts, and the snapshot commit. Scanner source is proposed under MIT; external tools remain separate installations under their own licenses.

## Architecture

Use Python 3.11+ for a small CLI and adapters. No service, privileged helper, runtime LLM, or shell script execution from KB contents. Target macOS 13+ on Apple Silicon and Intel; validate host-specific behavior on the available Mac and label untested architecture coverage.

The application is named Tocsin, with executable `tocsin` and Python package `tocsin`. Keep the common result model, KB reader, advisory normalization, reporting, and orchestration portable. Resolve platform capabilities at runtime through explicit adapters; do not import or invoke macOS-only tools on Linux or Windows. macOS is the only initial supported platform. Linux and Windows adapters are future milestones and must report unsupported until implemented and tested. Python is not assumed to ship with macOS; installation instructions must name the prerequisite.

Future Linux support will need distribution-specific package inventories and advisory matching, preserving epochs and vendor backports. Future Windows support will need installed-software inventory and vendor-specific identifiers and update channels. Package version ranges cannot be transferred across platforms. Portability of a shared engine does not establish tested platform support.

Modules have distinct responsibilities:

- CLI: parse explicit scan scopes and output options.
- Inventory: collect installed Homebrew formula identities and every installed version through Homebrew JSON, with auto-update disabled. Preserve tap, revision, architecture, and installation provenance where available. Casks and Apple system binaries are reported as outside initial vulnerability coverage.
- KB adapter: read bounded Markdown files, extracting status, update date, audit references, advisory references, and source paths. Use explicit aliases for versioned formulae; do not fuzzy-match package names. Missing or malformed pages produce unavailable context, never a clean verdict. Snapshot identity is read from `.git/HEAD` and ref files as bounded plain text; the adapter never runs `git` inside the user-supplied checkout, because repo-local git configuration can execute programs. Dirty state is reported as unknown.
- Dependency adapter: run a separately installed OSV-Scanner against user-selected project directories. Normalize its structured findings and declared coverage. Pin a tested supported tool version and reject unsupported output schemas. No project builds, install hooks, or dependency installation. Offline mode reads a local advisory database supplied with `--osv-database PATH`.
- Homebrew advisory adapter: match only reviewed formula-to-upstream mappings with primary-source affected ranges and applicability requirements. The first supported upstream is curl; other formulae still receive inventory and KB context and are explicitly marked unassessed. Establish curl mapping and records from upstream advisories during implementation. Do not import Linux distribution version ranges into Homebrew comparisons. Unknown build conditions or patch provenance yield needs-review. Extend coverage through additional reviewed adapters.
- Malware adapter: invoke local clamscan with a local signature database against selected paths. Configure recursion and resource bounds explicitly, and pair every limit with the engine's exceeds-limit and encrypted-content alert flags so skipped content is reported rather than passed as clean; prevent traversal outside scope through symlinks. Request alert-only output so captured output scales with alerts, not with the number of files. Distinguish signature matches, heuristic alerts, skipped/encrypted/oversized files, engine failures, and timeouts. Never pass deletion or quarantine flags.
- macOS posture adapter: read Gatekeeper, SIP, FileVault, and firewall status. Inventory launch agents and daemons by reading plists; report missing executables or clearly unsafe writable locations as review signals, not malware verdicts. Unknown command output or denied access produces an unknown check.
- Report: combine independent adapter outcomes without discarding findings when another adapter fails.

## User flow

Executable name: `tocsin`.

1. `tocsin doctor` reports operating system, available engines, versions, signature metadata, and KB readability; installs nothing.
2. `tocsin scan --brew [--kb PATH]` inventories Homebrew and attaches KB context and supported advisory checks.
3. `tocsin scan --project PATH (--online | --osv-database PATH) [--kb PATH]` checks supported dependency manifests using OSV-Scanner.
4. `tocsin scan --files PATH` runs an on-demand malware scan of that explicit path.
5. `tocsin scan --posture` checks macOS configuration and startup entries.
6. Scope flags can be combined. `--format json --output PATH` writes a machine-readable report; default output is readable terminal text. Existing files are not overwritten without an explicit overwrite flag.

No scan scope defaults to the whole home directory or disk. Installation and updating are documented manual steps for the first release. The KB is provided with an explicit local path and is optional for every scope; when it is absent, package-bearing checks record KB context as unavailable rather than failing. Default operations are local; project advisory lookups require `--online`, with help text explaining that package names and versions can be transmitted to advisory services. Offline dependency checks require a supported preloaded local advisory database supplied with `--osv-database PATH`; otherwise the adapter reports unavailable. File contents and reports are not uploaded by this application.

## Finding and coverage contract

Each result includes category, package/file/check identity, installed version when known, status, source-supplied severity (or unknown), confidence, evidence URLs or local evidence, suggested action, and observation time. KB context includes page path, snapshot commit when available, and last-reviewed date. Engine records include version, data age when available, completion state, and errors.

Statuses distinguish detected, needs-review, no-known-match, unassessed, skipped, and error. A no-known-match result is limited to the recorded source and scan coverage; the report never calls the computer safe. A package absent from the KB is unknown. An audit with no findings is historical context. Advisory matching is evidence of a known affected version, not proof that exploitation occurred.

Report exit codes: 0 means requested checks completed without actionable findings; 1 means completed with findings; 2 means at least one requested check is incomplete or failed, even if findings also exist. A check is incomplete when its completion state is not complete or when any of its findings is skipped or error. JSON retains both findings and errors. Coverage gaps for unsupported package families remain visible as unassessed findings and as assessed/unassessed counts in check metadata; they describe the limits of the assessment but do not by themselves make a check incomplete or change the exit code, because a Homebrew scan that only assesses curl would otherwise never be able to exit 0 or 1.

## Failure handling and implementation controls

Invoke tools with argument arrays and timeouts, bounded captured output, and no shell interpolation. Child processes receive a minimal explicit environment (search path, home, temporary directory, locale, plus per-call settings), not the user's full environment. Treat paths, filenames, Markdown, engine output, and advisories as untrusted data. Escape control characters in terminal output. Avoid parsing vulnerability identity from ambiguous filenames. Reject invalid feed schemas and unsupported versions; retain explicit errors. Do not follow links or execute instructions embedded in KB pages.

Keep scan evidence sufficient for review without collecting file contents. Store output with restrictive permissions. Signature freshness and advisory snapshot dates are visible; absent dates remain unknown. Do not silently fetch updates during a scan. Cancellation stops child processes and yields an incomplete outcome where reporting is possible.

## Verification and acceptance criteria

- Fixture tests cover actual KB status/table variants, missing pages, scoped and versioned package aliases, malformed content, and source attribution.
- Homebrew tests cover multiple installed versions, taps, revisions, missing Homebrew, and ambiguous upstream mapping. KB snapshot tests include a fixture checkout whose git configuration points at a program that must never run.
- Advisory tests cover introduced/fixed boundaries, multiple affected branches, backend restrictions, withdrawn advisories, unknown versions, and unassessed formulae. No generic string comparison or fixed-version-only inference.
- Adapter contract tests cover findings, successful empty results, invalid JSON, unsupported engine versions, nonzero exits, denied access, timeouts, and oversized output. Adapters accept an injected command runner so these cases run without real engines.
- File scope tests cover spaces, leading dashes, control characters, symlinks, and resource-limit reporting.
- Report tests ensure failed checks cannot yield success, unknown coverage cannot become clean, and mixed errors/findings survive JSON export.
- Optional local ClamAV integration uses the harmless EICAR test fixture in an isolated test directory when the engine and signatures are available; never use live malware.
- A read-only macOS smoke test verifies doctor, Homebrew inventory, KB enrichment, posture checks, and report output on the available host. Missing engines are reported explicitly rather than mocked as working in the final delivery.

## Delivery sequence

1. Build CLI, common result model, KB integration, and Homebrew inventory.
2. Add tested OSV-Scanner integration and reviewed curl advisory matching.
3. Add ClamAV and macOS posture adapters, preserving partial outcomes.
4. Verify fixtures and available live integrations; deliver install instructions, coverage matrix, sample reports, and local source project.

A later project can add a native desktop interface, broader formula/application mappings, controlled quarantine, and Endpoint Security integration. These do not block the on-demand first release. The planning documents will be saved in the private travis-burmaster/tocsin repository. Full-device scans and implementation are outside this documentation delivery.

## References

- KB schema: https://github.com/travis-burmaster/oss-security-kb/blob/main/SCHEMA.md
- KB methodology: https://github.com/travis-burmaster/oss-security-kb/blob/main/METHODOLOGY.md
- Homebrew interface: https://docs.brew.sh/Manpage
- ClamAV scan behavior: https://docs.clamav.net/manual/Usage/Scanning.html
- OSV-Scanner: https://google.github.io/osv-scanner/
- Apple Endpoint Security: https://developer.apple.com/documentation/endpointsecurity

## Design self-review

Reviewed for scope, ambiguous detection claims, Homebrew versus distro matching, missing-data behavior, dependency network privacy, and source attribution. Homebrew assessment intentionally starts with curl; inventory and KB enrichment cover other matching formulae without promising unsupported CVE detection. This is a design artifact; no scanner implementation or scan result is claimed.
