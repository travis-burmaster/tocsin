# Validation: what was verified live vs. fixture-only

This is the single index of what Tocsin's test suite and task reports
actually verified against a real engine or real host state, versus what
is exercised only through fixtures and fake `Runner`s. It exists so a
release decision never has to guess: every row below either names a real
command that was run and its result, or says explicitly that nothing real
was run for that item.

Host used for every "live" row below, unless noted otherwise:
**macOS 26.6.2 (build 25G83), arm64 (Apple Silicon)**, **Homebrew 6.0.19**,
**Python 3.13.13**. Intel Macs were never available and are untested (see
`docs/coverage.md`).

## Summary table

| Area | Verified live? | Date | Evidence |
|---|---|---|---|
| Homebrew inventory (`--brew`) | Yes -- real `brew info --json=v2 --installed` on this host | 2026-09-08 | Task 3 report, below |
| curl advisory matching (`assess_curl`) | Snapshot reviewed against upstream `curl.se/docs/vuln.json`; matching logic unit-tested only, no live-vulnerable curl install exercised | 2026-09-08 | `docs/evidence/curl-advisories.md` |
| OSV-Scanner dependency scan (`--project`) | Yes -- real osv-scanner v2.5.1 binary, real offline PyPI database, real detections | 2026-09-08 | Task 4 report, `docs/evidence/osv-contract.md`, below |
| ClamAV file scan (`--files`) | No -- no clamscan binary was ever available; a Docker probe was attempted and killed by the host for low memory | 2026-09-08 (attempt) | Task 6 report / `progress.md`, `docs/evidence/clamav-contract.md`, below |
| macOS posture + startup review (`--posture`) | Yes -- real `spctl`/`csrutil`/`fdesetup`/`socketfilterfw` and real launch-directory enumeration on this host | 2026-09-08 | Task 7 report, `docs/evidence/posture-contract.md`, below |
| Package build + install (isolated venv) | Yes -- `python -m build`, wheel install, `tocsin doctor` and a read-only `--posture` scan from the installed console script | 2026-09-08 | below |
| Linux / Windows scanning | No -- not implemented; portable fixture tests only (CI) | n/a | `docs/coverage.md` |

## Homebrew inventory (Task 3)

Command: `.venv/bin/tocsin scan --brew --kb <oss-security-kb clone>`
(read-only; no `brew install`/`upgrade`/`update`/`cleanup` was ever run,
only `brew info --json=v2 --installed` and, once, `brew --version`).

Result, quoted from the Task 3 report:

> - 99 `unassessed` findings (every installed formula/cask on this Mac).
> - Text report's coverage line:
>   `coverage: assessed=0 unassessed=99, kb_commit=30f536b7a81a681c340b2a37e044089623741ccb`
> - `curl` produced no finding because the Homebrew `curl` formula is not
>   installed on this Mac (only the Xcode CLT `/usr/bin/curl` is present)
>   -- correct behavior, not a bug.

Exit code: 0.

## OSV-Scanner dependency scan (Task 4)

Command (paraphrased from the gated integration test
`tests/test_osv.py::test_real_osv_scanner_offline_scan_detects_requests_cve`,
which runs the real binary end-to-end when `TOCSIN_OSV_SCANNER`/`TOCSIN_OSV_DB`
are set): the real osv-scanner v2.5.1 binary against a scratch
`requirements.txt` containing `requests==2.19.0`, offline, with a
populated PyPI-only offline database (both scratchpad-only, not part of
this repository).

Result, quoted from the Task 4 report:

> `scan_project` returned `completion == 'complete'` with 5 `detected`
> findings for real CVEs affecting `requests==2.19.0`,
> `metadata['engine'] == {'name': 'osv-scanner', 'version': '2.5.1'}`, and
> `report.exit_code([result]) == 1`.
>
> ```
> tests/test_osv.py::test_real_osv_scanner_offline_scan_detects_requests_cve PASSED
> ```

Exit code: 1 (complete, with findings). Re-run during the review-fix pass
(per `docs/evidence/osv-contract.md`) reproduced the same result.

This test is environment-gated and is **not** run in CI (see
`.github/workflows/tests.yml`); it requires a real osv-scanner binary and
a populated offline database neither of which are installed in CI.

## ClamAV file scan (Task 6) -- not verified against a real engine

No clamscan binary was available anywhere in this environment at any
point during implementation, and none was installed for this project
(installing engines is out of scope for Tocsin's own build/test process).
A Docker-based probe (`docker` pulling `clamav/clamav:stable`, intended to
exercise real return codes, `--stdout` stream routing, and exact
`Heuristics.*` alert strings against a live engine) was attempted in the
background during Task 6's review pass; quoted from `progress.md`:

> Task 6: ClamAV docker probe KILLED by the system for low memory before
> the image finished pulling (host already runs 5 containers); not
> retried. Ruling: the real-engine items stay documented as untested in
> docs/evidence/clamav-contract.md; final review should list them as
> pre-release verification work -- cost if wrong: an engine behaviour
> mismatch discovered only on a host with clamscan.

Every test in `tests/test_clamav.py` therefore runs against fixture text
(`tests/fixtures/clamav/`) and an injected fake `Runner`, never a real
subprocess. `docs/evidence/clamav-contract.md` records exactly which
flags, return codes, and output shapes are implemented from the
`clamscan(1)` man page rather than from an observed real run, and
`tests/test_clamav.py::test_real_clamscan_detects_eicar` remains an
optional, environment-gated integration test (`TOCSIN_CLAMSCAN`) that
anyone with a real clamscan install can run to close this gap -- it is
not run in CI.

**This is the single largest pre-release verification gap**: the ClamAV
adapter's engine contract (return codes, `--stdout` routing, alert string
formats) is implemented from documentation, not observed behavior.

## macOS posture and startup review (Task 7)

Command: `.venv/bin/tocsin scan --posture` (read-only; no setting was
altered).

Result, quoted from the Task 7 report:

> - Exit code: **2** (completion `partial`, due to one permission-denied
>   plist read, plus a `needs-review` finding).
> - Settings: gatekeeper enabled, sip enabled, filevault enabled,
>   **firewall disabled**, **firewall stealth mode disabled**.
> - Launch dirs: `~/Library/LaunchAgents` read/6 plists/0 symlinks;
>   `/Library/LaunchAgents` read/10 plists/0 symlinks;
>   `/Library/LaunchDaemons` read/15 plists/0 symlinks -- matches
>   posture-research.md's captured counts exactly.
> - Startup items: 31 total; 1 `needs-review` (a Homebrew launch agent
>   whose referenced executable no longer exists on disk); 1 `skipped`
>   (a LaunchDaemon plist owned by another user, permission denied on
>   read -- the cause of this run's `partial` completion); the rest
>   `no-known-match`.
> - Host: Darwin, release 26.6.2, machine arm64.

No plist contents are reproduced here or in the source report, per
project instructions; only counts and statuses.

## Isolated build and install verification (Task 8)

Performed in a scratch venv outside this repository
(`<scratchpad>/buildvenv`), built with
`/opt/homebrew/bin/python3.13` (never the project's own `.venv`, and
never system `python3`), to confirm the packaged wheel -- not the
editable checkout -- works end to end.

Commands run, in order:

```
/opt/homebrew/bin/python3.13 -m venv <scratchpad>/buildvenv
<scratchpad>/buildvenv/bin/pip install build
<scratchpad>/buildvenv/bin/python -m build          # from the repo root
<scratchpad>/buildvenv/bin/pip install dist/tocsin-0.1.0-py3-none-any.whl
<scratchpad>/buildvenv/bin/tocsin doctor
<scratchpad>/buildvenv/bin/tocsin scan --posture --format json --output <scratchpad>/posture.json
```

Result:

```
$ /opt/homebrew/bin/python3.13 --version
Python 3.13.13
$ /opt/homebrew/bin/python3.13 -m venv <scratchpad>/buildvenv
$ <scratchpad>/buildvenv/bin/pip install --upgrade pip build
$ <scratchpad>/buildvenv/bin/python -m build
...
adding 'tocsin/data/curl-advisories.json'
...
Successfully built tocsin-0.1.0.tar.gz and tocsin-0.1.0-py3-none-any.whl
$ <scratchpad>/buildvenv/bin/pip install dist/tocsin-0.1.0-py3-none-any.whl
$ <scratchpad>/buildvenv/bin/pip show tocsin
Name: tocsin
Version: 0.1.0
Summary: Evidence-based security scanner for malware, known software
  vulnerabilities, and operating-system security posture.
$ <scratchpad>/buildvenv/bin/tocsin doctor
platform: Darwin (arm64)
python: 3.13.13
capabilities: brew, files, posture, project
brew: Homebrew 6.0.19
clamscan: not found
osv-scanner: not found
$ <scratchpad>/buildvenv/bin/tocsin scan --posture --format json --output <scratchpad>/posture.json
$ echo $?
2
$ stat -f "%Sp" <scratchpad>/posture.json
-rw-------
```

The built wheel packages `tocsin/data/curl-advisories.json` (confirmed
present in the `python -m build` output above), the installed console
script (`tocsin`) runs correctly outside the repository and outside the
project's own `.venv`, `doctor` correctly reports `brew` found (real
Homebrew on this host) and `clamscan`/`osv-scanner` not found (neither is
installed on this host), and a real, read-only `--posture` scan produced
a valid JSON report (`schema_version: "1"`, one `partial` result with 36
findings -- consistent with the live posture behavior recorded in Task 7
and above, since posture always inspects the real host regardless of how
Tocsin was installed) written with file mode 0600. Exit code 2 matches
the `partial` completion. No setting was altered and nothing was
installed by Tocsin itself during this verification.

## What "fixture-only" means for the rows above

A fixture-only row means: the adapter's parsing, exit-code mapping, and
CLI wiring are covered by unit tests that inject a fake `Runner` returning
recorded or hand-written text, never a real subprocess talking to a real
engine. The engine *contract* (flags, return codes, output shape) each
adapter implements is still sourced from official documentation
(man pages, project docs) and, where available, from a real binary's
`--help`/`--version` output -- see each adapter's `docs/evidence/*.md` for
exactly which parts were confirmed against a real binary versus derived
from documentation alone.
