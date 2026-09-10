# Coverage matrix

What Tocsin actually assesses versus what it inventories as a coverage
gap, and what has been tested for real versus only through fixtures. See
`docs/evidence/validation.md` for the exact commands and dates behind
every "tested"/"untested" claim below, and each adapter's
`docs/evidence/*-contract.md` for the full engine contract.

## Platform

| Platform | Status |
|---|---|
| macOS 13+, Apple Silicon (arm64) | Supported. Read-only smoke-tested on macOS 26.6.2 (build 25G83), arm64, for `--brew` (Task 3) and `--posture` (Task 7); the `--project` (OSV-Scanner) and package build/install paths were also verified live on this same host (Task 4, Task 8). See `docs/evidence/validation.md`. |
| macOS 13+, Intel (x86_64) | Supported in code (no Apple-Silicon-only logic), but **untested** -- no Intel Mac was available during development. |
| Linux | **Not supported.** `supported_capabilities('Linux')` returns an empty set; every scan scope is reported `unavailable` with an explicit reason. Only the portable fixture test suite runs on Linux (CI). A green CI run on Linux does **not** mean Linux scanning is supported. |
| Windows | **Not supported.** Same as Linux: `supported_capabilities('Windows')` is empty, every scope reports explicitly unsupported. The bounded runner (`tocsin.runner.run_command`) also refuses to start any child process on a non-POSIX host (`os.name != 'posix'`), returning failure kind `unavailable`, rather than running unbounded. Only the portable fixture test suite runs on Windows (CI); several tests are skipped there (POSIX-only behavior) -- see "CI and Windows-skipped tests" below. |

## Homebrew (`--brew`)

- **Inventory**: every installed formula and cask, via
  `brew info --json=v2 --installed` (read-only; Tocsin never runs
  `install`/`upgrade`/`update`/`cleanup`).
- **Advisory assessment**: curl only. `src/tocsin/adapters/curl.py`
  matches an installed curl formula against six hand-reviewed advisory
  records in `src/tocsin/data/curl-advisories.json`
  (`docs/evidence/curl-advisories.md` has the per-record review and
  source citations). Every other formula and every cask is reported
  `unassessed` -- a coverage gap, not a clean verdict. `metadata['coverage']`
  on every `--brew` result reports the assessed/unassessed counts.
- The curl snapshot's six records are drawn from the ~215 advisories in
  curl's own `https://curl.se/docs/vuln.json` feed, filtered to the ones
  the OSS Security KB's curl page cites. A `no-known-match` verdict means
  "does not match one of these six reviewed records," never "curl has no
  vulnerabilities."

## Dependency scanning (`--project`)

- Engine: **OSV-Scanner v2.5.1** (osv-scalibr 0.5.2). `scan_project`'s
  version guard only accepts `2.5.x`; any other installed version is
  reported `unavailable` by both `tocsin doctor` and a `--project` scan.
  See `docs/evidence/osv-contract.md` for the full flag/exit-code
  contract.
- Both offline (`--osv-database PATH`) and online (`--online`) modes are
  implemented and tested with fake runners; the offline mode was also
  verified against the real v2.5.1 binary with a real offline PyPI
  database (Task 4; see `docs/evidence/validation.md`).
- **Manifest/ecosystem coverage is whatever OSV-Scanner itself supports**
  -- Tocsin does not maintain its own list. See osv-scanner's own
  supported-languages/lockfiles documentation:
  https://google.github.io/osv-scanner/supported-languages-and-lockfiles/
- Tocsin's own fixture and (for the offline case) real-binary tests only
  exercise `requirements.txt` (Python/PyPI) and `package-lock.json`
  (npm) manifests. Every other manifest format osv-scanner supports is
  untested by this project specifically, even though the engine itself
  supports it.
- `--no-resolve` is always passed: Tocsin never triggers dependency
  resolution (a build-adjacent operation the project's global
  constraints forbid).

## File scanning (`--files`)

- Engine: ClamAV (`clamscan`). **Verified live** against ClamAV 1.5.4
  (Homebrew bottle) on macOS 26.6.2 arm64, 2026-09-10: EICAR was detected
  end to end, a password-protected zip was reported `skipped` (evidence
  `Heuristics.Encrypted.Zip`), and the `Heuristics.Limits.Exceeded.*`
  oversized-file alert string was confirmed by a direct probe (see
  `docs/evidence/clamav-contract.md`, `docs/evidence/validation.md`).
  This is one engine version on one host, not a matrix -- a different
  clamscan version, a Linux/Windows build, or a different signature
  database has not been checked.
- Every flag, return code, and output format this adapter implements
  (`--stdout`, `--infected`, `--alert-exceeds-max`, `--alert-encrypted`,
  the `<path>: <name> FOUND` line shape, return codes 0/1/2) is sourced
  from the `clamscan(1)` man page and cross-referenced against the
  ClamAV source, recorded in full in `docs/evidence/clamav-contract.md`,
  and the flags/return-code precedence/output-routing behavior above have
  now been confirmed against the real 1.5.4 binary rather than the man
  page alone. The live probes also surfaced a real reporting gap now
  fixed: ClamAV 1.5.4 emits no per-file diagnostic at all for a
  permission-denied file under `--infected`; the adapter now parses the
  summary block's `Total errors`/`Scanned files` lines to report that gap
  explicitly instead of an uninformative `(no stderr)` error.
- `tests/test_clamav.py::test_real_clamscan_detects_eicar` and two
  further gated live tests (`test_real_clamscan_unreadable_file_is_informative_error`,
  `test_real_clamscan_undersized_random_file_not_flagged`) are optional,
  environment-gated (`TOCSIN_CLAMSCAN`) integration tests; all three have
  been run and passed against the real 1.5.4 engine, and are never run in
  CI.
- Limits: 100 MB per-file (`--max-filesize`), 500 MB per-container
  (`--max-scansize`, overriding the engine's 400 MB default), 20 levels
  of archive recursion (`--max-recursion`), a 300-second scan timeout,
  and a 100,000-file enumeration cap. All surfaced in
  `CheckResult.metadata['limits']`.
- Feature detection instead of a version pin: since no real binary was
  ever available to verify a specific version against, `scan_files` and
  `doctor` both check `clamscan --help` for every required flag rather
  than pinning a tested version number.

## macOS security posture and startup review (`--posture`)

- Five settings checked via real macOS commands, with **exact recognized
  phrases** captured on macOS 26.6.2 (build 25G83, arm64) and recorded in
  `docs/evidence/posture-contract.md`: Gatekeeper (`spctl --status`), SIP
  (`csrutil status`), FileVault (`fdesetup status`), firewall
  (`socketfilterfw --getglobalstate`), and firewall stealth mode
  (`socketfilterfw --getstealthmode`). Anything other than an exact
  recognized phrase (including SIP's "Custom Configuration" or a future
  deprecation notice) is reported `unknown`/`unassessed`, never guessed.
- Startup-item inventory covers exactly three launch directories:
  `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and
  `/Library/LaunchDaemons`. **`/System/Library/LaunchAgents` and
  `/System/Library/LaunchDaemons` are deliberately excluded** (465 and
  422 plists respectively on the research host, all on the Apple-signed
  system volume) -- a documented limitation, not an oversight. This
  inventory is not exhaustive persistence detection: login items, cron,
  periodic scripts, and code-signature checks are all out of scope,
  which is also recorded in `metadata['limitations']` on every result.
- Read-only smoke-tested live on macOS 26.6.2 arm64 (Task 7; see
  `docs/evidence/validation.md`): exit code 2 (`partial`, due to one
  permission-denied plist), firewall and firewall-stealth both found
  disabled, 31 startup items inventoried across the three directories.
- Exit codes follow the shared policy: `enabled`/`no-known-match`
  settings and inventoried startup items never raise the exit code past
  what other findings already require; a `disabled` setting or a
  `needs-review` startup item raises it to at least 1; any `partial`
  completion (e.g. a denied directory, or a `skipped` malformed plist)
  raises it to 2.

## Knowledge-base context (`--kb`)

The OSS Security KB (a local, optional checkout) provides **context
only** -- source references, audit history, snapshot commit -- never a
verdict. `--kb` is optional for every scope; without it, package-bearing
checks record KB context as `unavailable` and never report a clean KB
finding. A missing KB page for a package is never treated as evidence the
package is safe.

## CI and Windows-skipped tests

`.github/workflows/tests.yml` runs the full portable test suite on
`macos-latest`, `ubuntu-latest`, and `windows-latest`, on Python 3.11 and
3.13, with only `pip install -e .[test]` -- no real engine, no signature
database, and no scan of the runner host is ever installed or run in CI.
**A passing CI run on Linux or Windows does not mean scanning is
supported there** -- see the Platform section above.

The following tests are skipped on non-POSIX hosts (`os.name != 'posix'`)
because they exercise behavior that either does not exist on Windows or
is unreliable there without elevated privilege, with the reason given
inline at each skip:

| Test | File | Why it can't run on Windows |
|---|---|---|
| `test_output_file_created_with_mode_0600` | `tests/test_cli.py` | POSIX file-mode bits (0600) do not apply on Windows. |
| `test_existing_output_replaced_with_overwrite` | `tests/test_cli.py` | Same. |
| `test_symlink_inside_root_not_followed` | `tests/test_clamav.py` | Creating a symlink requires elevated privilege on Windows. |
| `test_temp_file_mode_0600_and_deleted_after` | `tests/test_clamav.py` | POSIX file-mode bits (0600) do not apply on Windows. |
| `test_symlink_escape_is_rejected` | `tests/test_kb.py` | Creating a symlink requires elevated privilege on Windows. |
| `test_denied_launch_dir_is_error_string_and_partial` | `tests/test_posture.py` | Uses `os.geteuid()` (does not exist on Windows) and `chmod`-based permission denial. |
| `test_launch_dir_with_unsearchable_parent_is_denied_and_partial` | `tests/test_posture.py` | Same. |
| `test_symlinked_plist_skipped_and_counted` | `tests/test_posture.py` | Creating a symlink requires elevated privilege on Windows. |
| Every test in `tests/test_runner.py` prefixed `posix_only` (process start/kill/permission/exec tests) | `tests/test_runner.py` | Requires POSIX process groups (`os.killpg`, `start_new_session`); `run_command` itself refuses to start anything on a non-POSIX host, which is exercised separately by `test_windows_returns_unavailable_without_starting_anything` (portable, monkeypatches `os.name`). |

Skipping is one of two mechanisms that keep the CI matrix green off
macOS. The other: `supported_capabilities()` (`src/tocsin/platforms/__init__.py`)
is empty for every platform except `'Darwin'`, so any CLI-level test that
needs to actually reach an adapter -- not the platform-capability gate
itself -- must force Darwin regardless of the real host running pytest.
`tests/conftest.py`'s `force_darwin` fixture does this (monkeypatching
`tocsin.cli`'s `platform.system`) and is used throughout
`tests/test_cli.py` and `tests/test_integration.py`; the
unsupported-platform-scope tests use the same lever in the other
direction, forcing `'Linux'` to prove a scope is reported unsupported
rather than silently skipped.

The environment-gated real-engine integration tests
(`test_real_clamscan_detects_eicar`, `test_real_osv_scanner_offline_scan_detects_requests_cve`)
are skipped everywhere, including in CI, unless their `TOCSIN_*`
environment variables are set by hand -- CI deliberately never sets them.
