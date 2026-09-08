# Tocsin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This document does not authorize starting implementation or publishing a release.

**Goal:** Build an on-demand macOS security CLI with malware scanning, supported-package vulnerability checks, source-linked KB context, and honest coverage reporting, using a portable core for future Linux and Windows adapters.

**Architecture:** A Python CLI orchestrates independent adapters and normalizes their results. Common inventory identities, findings, KB context, and reports are platform-independent; operating-system commands and package semantics belong to platform adapters. External scanner integrations are version-tested and optional, with explicit unavailable outcomes.

**Tech Stack:** Python 3.11+, standard-library argparse/dataclasses/json/subprocess/plistlib, pytest for tests, separately installed ClamAV and OSV-Scanner, Homebrew JSON, local OSS Security KB snapshot.

**Spec:** [Tocsin design](../specs/2026-09-08-tocsin-design.md). Read both documents before implementation. All paths below are relative to the repository root. Code blocks describe proposed interfaces or tests, not existing functionality.

## Global Constraints

- Executable and Python package name: `tocsin`.
- Use Python 3.11+ for a small CLI and adapters.
- Target macOS 13+ on Apple Silicon and Intel; validate host-specific behavior on the available Mac and label untested architecture coverage.
- macOS is the only initial supported platform. Linux and Windows adapters are future milestones and must report unsupported until implemented and tested.
- No scan scope defaults to the whole home directory or disk.
- No project builds, install hooks, or dependency installation.
- Do not silently fetch updates during a scan.
- Unknown build conditions or patch provenance yield needs-review.
- No generic string comparison or fixed-version-only inference.
- File contents and reports are not uploaded by this application.
- Online advisory lookups require explicit `--online`; offline dependency checks read a local database supplied with `--osv-database PATH`, and absence of usable data produces an incomplete check.
- Exit 0: complete without actionable findings; exit 1: complete with findings; exit 2: partial or failed, retaining any findings. A check is incomplete when its completion is not `complete` or when it carries any `error` or `skipped` finding. Coverage gaps (`unassessed` findings) are visible in findings and coverage metadata but do not by themselves make a check incomplete.
- `--kb PATH` is optional for every scope. When absent, package-bearing checks record KB context as `unavailable`; they never report a clean KB verdict.
- Never execute code from KB contents. This includes running `git` inside a user-supplied KB checkout, because repo-local `.git/config` can set `core.fsmonitor` or `core.hooksPath`.
- Preserve KB attribution, transformation notices, source date, and snapshot commit. A missing page or advisory never means safe.

## File structure and shared contracts

```text
pyproject.toml                         packaging, console entry point, test dependency
src/tocsin/__init__.py                 version
src/tocsin/cli.py                      argument parsing and orchestration
src/tocsin/models.py                   common identities, findings, adapter outcomes
src/tocsin/report.py                   text/JSON formatting and exit policy
src/tocsin/runner.py                   bounded subprocess invocation
src/tocsin/kb.py                       local Markdown context extraction
src/tocsin/platforms/__init__.py        capability selection
src/tocsin/platforms/macos.py           Homebrew inventory and posture
src/tocsin/adapters/osv.py              dependency scanner normalization
src/tocsin/adapters/clamav.py           selected-file scan normalization
src/tocsin/adapters/curl.py             reviewed curl advisory matching
data/curl-advisories.json              source-linked reviewed advisory snapshot
tests/test_*.py                        focused behavioral tests
tests/fixtures/                        attributed KB and tool-output fixtures
docs/coverage.md                       assessed, unassessed, and tested coverage
docs/development.md                    setup and verification instructions
docs/evidence/                        engine versions, feed research, validation records
```

Use these shared contracts consistently; implement their definitions in Tasks 1 and 2:

```python
@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    provenance: dict[str, str]

@dataclass(frozen=True)
class Finding:
    category: str
    subject: str
    status: str  # detected, needs-review, no-known-match, unassessed, skipped, error
    severity: str
    confidence: str
    evidence: tuple[str, ...]
    action: str
    observed_at: str

@dataclass(frozen=True)
class CheckResult:
    name: str
    completion: str  # complete, partial, unavailable, error
    findings: tuple[Finding, ...]
    errors: tuple[str, ...]
    metadata: dict[str, object]
    # Invariant: a result containing any finding with status 'error' or
    # 'skipped' must not have completion 'complete'. exit_code enforces this
    # defensively; adapters must also set partial themselves.

@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    stdout: str
    stderr: str
    failure: str | None  # missing, timeout, cancelled, output-limit, permission

Runner = Callable[..., CommandResult]  # signature of run_command

def exit_code(results: list[CheckResult]) -> int: ...
def run_command(argv: list[str], *, timeout: float, max_bytes: int,
                extra_env: dict[str, str] | None = None) -> CommandResult: ...
```

`run_command` never inherits the caller's environment wholesale. It builds a minimal base environment from the current process containing only `PATH`, `HOME`, `TMPDIR`, and `LANG` (defaulting `LANG` to `C.UTF-8`), then overlays `extra_env`. Everything else, including `HOMEBREW_*`, `DYLD_*`, and `LD_*` variables, is dropped. `PATH` is inherited because separately installed engines live in user-chosen locations such as `/opt/homebrew/bin`.

Every adapter entry point that runs external commands accepts `runner: Runner = run_command` as a keyword argument so tests inject fake command outcomes without monkeypatching module attributes and without touching real binaries.

Completion vocabulary: `complete` means the check ran over its whole requested scope; `partial` means it ran but some scope was not covered (denied access, resource limits, unparseable input, output budget); `unavailable` means the engine, database, or KB needed for the check was absent; `error` means the engine ran and failed. Unassessed packages are coverage gaps recorded as `unassessed` findings plus an `assessed`/`unassessed` count in `metadata['coverage']`; they do not change completion.

Unknown metadata is explicitly null, not silently filled with current dates. JSON reports add schema_version, generated_at, host platform/architecture, requested scopes, and results. Package findings include the installed version in subject and structured package metadata in their check result.

## Task 1: Runnable CLI with truthful report outcomes

**Files:** Create `pyproject.toml`, `src/tocsin/__init__.py`, `src/tocsin/cli.py`, `src/tocsin/models.py`, `src/tocsin/report.py`, `tests/test_report.py`, `tests/test_cli.py`.

**Interfaces:** Produce the model types above, `exit_code(results)`, `render_json(results, context) -> str`, and `main(argv: list[str] | None = None) -> int`.

- [ ] Write tests for incomplete-result precedence and rejection of an empty scan scope:

```python
def test_incomplete_check_wins_over_no_findings():
    result = CheckResult('clamav', 'unavailable', (), ('engine missing',), {})
    assert exit_code([result]) == 2

def test_empty_scope_rejected():
    assert main(['scan']) == 2

def test_error_finding_makes_complete_check_incomplete():
    finding = Finding('dependency', 'requirements.txt', 'error', 'unknown',
                      'high', ('parse failure',), 'review manifest', '2026-09-08T00:00:00Z')
    result = CheckResult('osv', 'complete', (finding,), (), {})
    assert exit_code([result]) == 2

def test_unassessed_coverage_gap_does_not_force_exit_2():
    finding = Finding('package', 'openssl@3 3.3.0', 'unassessed', 'unknown',
                      'high', (), 'no reviewed advisory adapter', '2026-09-08T00:00:00Z')
    result = CheckResult('brew', 'complete', (finding,), (), {'coverage': {'assessed': 1, 'unassessed': 1}})
    assert exit_code([result]) == 0
```

- [ ] Run `python -m pytest tests/test_report.py tests/test_cli.py -q`; verify the missing modules fail before implementation.
- [ ] Implement dataclasses, argparse scopes, `doctor`, and report serialization. Define the console entry point as `tocsin = "tocsin.cli:main"`. Scan options include `--kb PATH` (optional for every scope), `--online`, `--osv-database PATH`, `--format`, `--output`, and `--overwrite`. Initially requested adapters return unavailable. Implement the exit rule:

```python
INCOMPLETE_STATUSES = {'error', 'skipped'}
ACTIONABLE_STATUSES = {'detected', 'needs-review'}

if any(r.completion != 'complete' for r in results):
    return 2
if any(f.status in INCOMPLETE_STATUSES for r in results for f in r.findings):
    return 2
if any(f.status in ACTIONABLE_STATUSES for r in results for f in r.findings):
    return 1
return 0
```

`unassessed` and `no-known-match` findings never change the exit code on their own; they are visible in the report and in coverage metadata.

- [ ] Add tests preserving mixed findings/errors and round-tripping JSON. Escape terminal control characters and create reports exclusively with mode 0600; add tests that existing output is rejected unless `--overwrite` is explicit.
- [ ] Run the two test modules and `tocsin --help` in a local virtual environment. Commit as `feat: add Tocsin CLI and report contracts`.

## Task 2: Bounded tool execution and platform selection

**Files:** Create `src/tocsin/runner.py`, `src/tocsin/platforms/__init__.py`, `tests/test_runner.py`, `tests/test_platforms.py`; update CLI doctor.

**Interfaces:** Produce `run_command` above and `supported_capabilities(system: str) -> frozenset[str]`. macOS exposes brew/posture/files/project only after their adapters are integrated; other platforms initially expose no scan capabilities.

- [ ] Write failure and unsupported-platform tests:

```python
def test_linux_does_not_claim_macos_checks():
    assert 'brew' not in supported_capabilities('Linux')

def test_missing_command_is_explicit():
    result = run_command(['/nonexistent/tocsin-tool'], timeout=1, max_bytes=1024)
    assert result.failure == 'missing'

def test_child_environment_is_minimal(monkeypatch):
    monkeypatch.setenv('HOMEBREW_LEAKED', '1')
    monkeypatch.setenv('DYLD_INSERT_LIBRARIES', '/tmp/x.dylib')
    result = run_command([sys.executable, '-c',
                         'import os, json; print(json.dumps(dict(os.environ)))'],
                         timeout=5, max_bytes=65536, extra_env={'TOCSIN_TEST': 'y'})
    env = json.loads(result.stdout)
    assert 'HOMEBREW_LEAKED' not in env and 'DYLD_INSERT_LIBRARIES' not in env
    assert env['TOCSIN_TEST'] == 'y'
    assert 'PATH' in env and 'HOME' in env
```

- [ ] Run `python -m pytest tests/test_runner.py tests/test_platforms.py -q` and verify failure.
- [ ] Implement array-only subprocess calls with `shell=False` and the minimal base environment defined in the shared contracts (`PATH`, `HOME`, `TMPDIR`, `LANG` only, plus `extra_env`). Drain stdout and stderr concurrently with a combined byte budget, terminate the process group on timeout/output overflow/cancellation, and reap children. On overflow, return the captured prefix with `failure='output-limit'` so adapters can keep already-parsed findings and mark the check partial rather than discarding completed work. POSIX process groups are implemented first behind a platform boundary; unsupported Windows execution remains unavailable. Never start macOS commands from another platform.
- [ ] Test a sleeping child, a child flooding both streams, literal spaces/leading dashes in arguments, nonzero exit, and interrupt cleanup using harmless Python fixture programs. Doctor discovers engines without installing them and reports unsupported versions as such.
- [ ] Run both modules; commit as `feat: bound external commands and select platform capabilities`.

## Task 3: KB context and Homebrew inventory

**Files:** Create `src/tocsin/kb.py`, `src/tocsin/platforms/macos.py`, `tests/test_kb.py`, `tests/test_homebrew.py`, `tests/fixtures/kb/`; update CLI/report.

**Interfaces:** `read_kb(root: Path, package: Package) -> dict[str, object]`; `kb_snapshot(root: Path) -> dict[str, object]`; `parse_brew(payload: str) -> list[Package]`; `inventory_brew(*, kb_root: Path | None = None, runner: Runner = run_command) -> CheckResult`. Inventory metadata holds serialized packages, their KB context (or `unavailable` when no `--kb` was given), and the KB snapshot identity.

- [ ] Write the unknown-coverage test and fixtures for the actual curl and openssl@3 page variants:

```python
def test_missing_kb_page_is_unknown(tmp_path):
    package = Package('homebrew', 'absent', '1.0', {})
    context = read_kb(tmp_path, package)
    assert context['status'] == 'unknown'
```

- [ ] Run `python -m pytest tests/test_kb.py tests/test_homebrew.py -q`; confirm failure.
- [ ] Parse `brew info --json=v2 --installed` through the injected runner with `extra_env={'HOMEBREW_NO_AUTO_UPDATE': '1'}`. Preserve every installed version, full name/tap, revision, and architecture when provided. Split a Homebrew revision suffix (`8.0.0_1`) into `version='8.0.0'` and `provenance['revision']='1'` at inventory time so downstream matchers never see underscores. Keep casks separate as unassessed. Do not merge third-party formulae into core names. Record `metadata['coverage']` with assessed and unassessed counts; unassessed formulae do not make the check partial.
- [ ] Resolve KB pages through a checked ecosystem map and explicit aliases. Bound each page to 1 MiB; reject traversal and paths resolving outside the supplied KB root. Extract status/date/source links without executing Markdown. Attribute copied fixture excerpts with original URLs and license notices.
- [ ] Implement `kb_snapshot` without invoking `git`: read `.git/HEAD` as a bounded plain file (4 KiB); if it is a symbolic ref, resolve it by reading `.git/<ref>` and then `.git/packed-refs`, each bounded and validated as a 40- or 64-hex commit id. Anything else yields `commit: null`. Working-tree dirty state is not determined and is reported as `dirty: null`. Running `git status` or `git describe --dirty` inside the KB checkout is forbidden because repo-local `core.fsmonitor` and `core.hooksPath` execute arbitrary programs.
- [ ] Test scoped npm aliases, versioned formula names, malformed tables/JSON, stub status, missing Homebrew (fake runner returning `failure='missing'`), multiple versions, revision splitting, symlink escape, and snapshot reading against fixture `.git` directories with direct HEAD, symbolic HEAD, packed refs, and a `.git/config` containing `fsmonitor = /bin/false` that must never run. Run both modules and a read-only inventory smoke test; commit as `feat: attach knowledge-base context to Homebrew inventory`.

## Task 4: Supported project dependency vulnerabilities

**Files:** Create `src/tocsin/adapters/osv.py`, `tests/test_osv.py`, `tests/fixtures/osv/`, `docs/evidence/osv-contract.md`; update CLI.

**Interfaces:** `scan_project(path: Path, *, online: bool, database: Path | None, kb_root: Path | None = None, runner: Runner = run_command) -> CheckResult`; `normalize_osv(payload: str) -> CheckResult`. `database` is supplied by the `--osv-database PATH` CLI flag; `kb_root` by `--kb`.

- [ ] Write a test ensuring offline scans with no database never call the network-capable engine:

```python
def test_offline_without_database_is_unavailable(tmp_path):
    result = scan_project(tmp_path, online=False, database=None)
    assert result.completion == 'unavailable'
```

- [ ] Run `python -m pytest tests/test_osv.py -q`; confirm failure.
- [ ] Select an available stable OSV-Scanner version and record its exact version, official documentation URL, source-scan flags, JSON schema, offline database support and expected local database layout, and exit semantics in the contract document. Check the installed executable's help/version before wiring arguments; do not invent flags from a different release. If offline is unsupported, return unavailable for offline requests and say so in `--osv-database` help text.
- [ ] Implement version-guarded invocation and normalization. Online mode is explicit. Offline mode passes the `--osv-database` directory to the engine and returns unavailable when it is absent or unreadable. Preserve advisory IDs, affected installed version, aliases, source severity, fix information, and manifest location. Reject malformed or unknown schemas. Do not execute dependency resolution/builds. Derive tested manifest coverage from fixtures and engine output; unrecognized manifests remain unassessed. An unparseable manifest among several yields an `error` finding for that manifest and completion `partial`, never `complete`.
- [ ] Add version rejection, malformed JSON, timeout, nonzero failure, findings exit, empty success, and mixed unsupported-manifest fixtures. Run the module and a harmless vulnerable-lockfile integration when available; commit as `feat: integrate dependency advisory scanning`.

## Task 5: Evidence-backed Homebrew curl matching

**Files:** Create `src/tocsin/adapters/curl.py`, `data/curl-advisories.json`, `tests/test_curl.py`, `docs/evidence/curl-advisories.md`.

**Interfaces:** `parse_release(value: str) -> tuple[int, int, int] | None`; `assess_curl(package: Package, records: list[dict]) -> CheckResult`. `parse_release` accepts only the exact form `^[0-9]+\.[0-9]+\.[0-9]+$` with ASCII digits (anchored regex; no `int()` on arbitrary text, so `8.0.0_1`, `8.1.0-rc1`, `8.1.0-DEV`, and whitespace all return `None`). A `None` installed version yields a `needs-review` finding with the raw version as evidence, never `no-known-match` and never an `error` check. Homebrew revisions arrive already split into `provenance['revision']` by Task 3 and are evaluated separately.

- [ ] Write semantic-order and unknown-applicability tests:

```python
def test_release_order():
    assert parse_release('8.10.0') > parse_release('8.9.0')

def test_non_release_versions_are_not_comparable():
    for raw in ('8.1.0-rc1', '8.1.0-DEV', '8.0.0_1', '8.1', ' 8.1.0', '8.1.0\n'):
        assert parse_release(raw) is None

def test_prerelease_is_needs_review_not_clean():
    package = Package('homebrew', 'curl', '8.1.0-rc1', {})
    record = {'id': 'TEST-ONLY', 'introduced': '7.0.0', 'fixed': '8.1.0', 'source': 'fixture'}
    result = assess_curl(package, [record])
    assert result.findings[0].status == 'needs-review'

def test_unknown_build_is_not_confirmed_vulnerable():
    package = Package('homebrew', 'curl', '8.0.0', {})
    record = {'id': 'TEST-ONLY', 'introduced': '7.0.0', 'fixed': '8.1.0',
              'requires': {'tls_backend': 'gnutls'}, 'source': 'fixture'}
    result = assess_curl(package, [record])
    assert result.findings[0].status == 'needs-review'
```

- [ ] Run `python -m pytest tests/test_curl.py -q`; confirm failure.
- [ ] Review primary upstream curl advisories referenced by the KB, obtaining affected lower/upper boundaries, fixes, prerequisites, publication/update dates, severity source, and withdrawal state. Record each source URL and review date. Commit only records with established upstream identity and ranges; source text alone must not be promoted into a confirmed local match.
- [ ] Implement schema validation and bounded numeric ranges, evaluating backend/provenance restrictions before detected status. Unknown revisions or third-party patches produce needs-review. Fixed versions are excluded. Withdrawn records cannot yield detected. Unsupported formulae remain unassessed, and a finite curated snapshot is explicitly partial coverage rather than the full curl advisory history.
- [ ] Test branch boundaries, prereleases, invalid versions, withdrawal, missing prerequisites, and stale/unknown data dates. Review feed attribution and all record evidence; run tests and commit as `feat: add reviewed curl vulnerability matching`.

## Task 6: Selected-file ClamAV scanning

**Files:** Create `src/tocsin/adapters/clamav.py`, `tests/test_clamav.py`, `tests/fixtures/clamav/`, `docs/evidence/clamav-contract.md`.

**Interfaces:** `scan_files(path: Path, *, runner: Runner = run_command) -> CheckResult`. Use the common runner and preserve engine/signature metadata.

- [ ] Write missing-engine, non-followed symlink, error-not-clean, and limit-exceeded tests. Inject a fake runner returning `CommandResult(2, '', 'database unavailable', None)` and assert completion is error with no no-known-match finding. Inject a fake runner whose stdout contains a `Heuristics.Limits.Exceeded` alert line and assert the file gets a `skipped` finding and completion `partial`.
- [ ] Run `python -m pytest tests/test_clamav.py -q`; confirm failure.
- [ ] Record a tested engine version and supported flags. Inventory regular files within the selected root without following symlinks; bound individual scan size to 100 MiB, total expanded scan data per container to 500 MiB, recursion to 20, and operation timeout to 300 seconds. Every limit flag is paired with `--alert-exceeds-max=yes` so files or container members beyond a limit are reported as `Heuristics.Limits.Exceeded` alerts instead of `OK`; pass `--alert-encrypted=yes` so encrypted archives and documents are reported rather than silently passed. Surface configured limits in report metadata. Confirm installed tool support for each flag before supplying it; if the installed engine lacks `--alert-exceeds-max`, the check is `unavailable`, because oversized content could otherwise be reported clean. Skip ambiguous control-character filenames with an explicit incomplete outcome unless the engine provides unambiguous structured identity output.
- [ ] Invoke clamscan with `--infected` (only alert lines and the summary are printed) and `--stdout`, so captured output scales with alerts rather than with the number of scanned files and the runner's byte budget is not a hidden cap on tree size. Take scanned-file and scanned-data counts from the summary block for metadata. If the runner still reports `output-limit`, keep the findings parsed from the captured prefix and mark the check partial. Implement scanning with absolute path arguments and no removal/move/copy flags. Map `Heuristics.Limits.Exceeded` and `Heuristics.Encrypted.*` alerts to `skipped` findings with the alert name as evidence, and keep signature matches (`detected`) separate from other heuristic alerts (`needs-review`). Resource limits, permission failures, and parse ambiguity mean partial. Report engine and signature dates; do not download signatures automatically. Treat file replacement during scanning as a limitation and never offer automatic remediation based on a path-only result.
- [ ] Test spaces, leading dashes, newlines, symlinks, oversized files and container members, encrypted archives, output-limit recovery, mixed detections/errors, absent signatures, and cancellation. Optionally run EICAR in an isolated temporary directory with an installed engine, documenting the outcome and leaving no live malware. Commit as `feat: add bounded on-demand malware scans`.

## Task 7: macOS configuration and startup review

**Files:** Update `src/tocsin/platforms/macos.py`; create `tests/test_posture.py`, `tests/fixtures/posture/`.

**Interfaces:** `scan_posture(*, runner: Runner = run_command) -> CheckResult`; `parse_setting(name: str, returncode: int, output: str) -> str` returning enabled/disabled/unknown. Denied-directory tests inject a fake plist directory listing rather than changing real permissions.

- [ ] Write tests for unfamiliar output and unsuccessful commands:

```python
def test_unrecognized_setting_remains_unknown():
    assert parse_setting('sip', 0, 'unexpected future response') == 'unknown'
```

- [ ] Run `python -m pytest tests/test_posture.py -q`; confirm failure.
- [ ] Read status using verified local `spctl --status`, `csrutil status`, `fdesetup status`, and application-firewall status commands. Parse recognized responses only; include raw bounded evidence and unknown results for denial/deprecation/changed wording. Do not alter any setting or escalate automatically.
- [ ] Read bounded plists from user/system LaunchAgents and LaunchDaemons. Extract Program/ProgramArguments without execution. Missing referenced executables and confirmed unsafe writable locations yield needs-review; absent signatures alone are not malware findings. Record access-denied directories as partial inventory. Do not equate startup plist inventory with exhaustive persistence detection.
- [ ] Test malformed plists, absent executables, denied directories, unknown status, disabled settings, and benign unsigned entries. Run a read-only smoke test on the available Mac and record OS/architecture; commit as `feat: report macOS posture and startup review signals`.

## Task 8: Integrated release-readiness documentation

**Files:** Update CLI, README, and `pyproject.toml`; create `tests/test_integration.py`, `docs/coverage.md`, `docs/development.md`, `.github/workflows/tests.yml`, `.gitignore`.

**Interfaces:** All four scopes use the shared outcome/report contracts. Doctor reports tool version compatibility and signature/database availability.

- [ ] Write an orchestration test with a detected finding from one adapter and unavailable status from another; assert both appear in JSON and exit is 2. Add a test that a requested unsupported platform scope is never silently ignored.
- [ ] Run `python -m pytest tests/test_integration.py -q`; confirm failures for missing wiring.
- [ ] Wire adapters, cancellation, consistent timestamps, context enrichment, and explicit privacy flags. `--kb` is optional for every scope; brew and project checks record KB context as `unavailable` when it is absent. `--osv-database` is documented alongside `--online` as the offline alternative. Enable a capability only once integrated. Add package metadata without claiming an unverified globally available PyPI name. Proposed MIT source license needs an explicit licensing decision before release; KB/engine licenses remain separate.
- [ ] Document virtual-environment installation from source, external engine setup, manual signature/data updates including the OSV offline database, sample reports, privacy behavior, exit codes (including that `unassessed` coverage gaps do not raise the exit code while `error`/`skipped` findings do), and exact tested tool versions. Coverage matrix separates macOS Intel/Apple Silicon tests, unassessed Homebrew packages, curated curl records, supported dependency formats, file limits, and future Linux/Windows support.
- [ ] Configure CI to run portable fixture tests on macOS, Ubuntu, and Windows with Python 3.11 and a current supported Python version; mark OS-specific cases explicitly. Passing portable tests does not mark Linux/Windows scans supported. Do not upload private scan reports or run real host scans in CI.
- [ ] Run `python -m pytest -q`, build/install the package in an isolated environment, and run doctor plus read-only smoke checks. Record real versus fixture-only verification in `docs/evidence/validation.md`. Commit as `docs: document Tocsin coverage and verified setup`. Publishing or changing repository visibility requires a separate user request.

## Future platform milestones

Linux and Windows are intentionally outside the first implementation cycle. Each requires a focused design and acceptance plan before coding:

- Linux: distro/package identity including epochs and vendor revisions; vendor advisory sources and backport semantics; explicit distro support matrix; selected-file and project-scan verification; Linux-specific posture checks.
- Windows: installed application and package-manager identity; update-channel and architecture matching; vendor advisories; Windows process/path/permission behavior; selected-file and project-scan verification; Windows-specific posture checks.
- Both: implement native runner cancellation and output-permission semantics, validate engine support, preserve the common JSON contract, and prove unavailable checks remain explicit. Never reuse Homebrew matching logic for these inventories.

## Plan self-review

The eight tasks cover the initial design: CLI/reporting (1, 8), subprocess and platform boundaries (2), KB/inventory (3), dependencies (4), Homebrew advisory applicability (5), malware and scope limits (6), posture/startup review (7), and validation/setup (8). Scope remains macOS first. External engine contract discovery is an explicit deliverable before adapter implementation, because versions and output formats must be verified rather than guessed. Future OS support and a public release are separate milestones. No implementation tasks are marked complete by saving this plan.
