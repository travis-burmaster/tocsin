# OSV-Scanner engine contract (evidence)

Adapter: `src/tocsin/adapters/osv.py`. This records the exact engine
contract the adapter implements, so a future version bump is a deliberate,
re-verified decision rather than an assumption.

## Tested version

- **osv-scanner v2.5.1** (osv-scalibr 0.5.2), commit `c84fa4568f2526d0333e9a914ea8a0a5f74ad68b`,
  release date **2026-08-17**, platform `darwin_arm64`.
- Confirmed directly against the binary with `osv-scanner --version`:
  ```
  osv-scanner version: 2.5.1
  osv-scalibr version: 0.5.2
  commit: c84fa4568f2526d0333e9a914ea8a0a5f74ad68b
  built at: 2026-08-17T03:44:26Z
  ```
- `scan_project`'s version guard only accepts major.minor `2.5`; any other
  version (parsed from that same `osv-scanner version: X.Y.Z` line) is
  reported `unavailable`, naming both the found version and this tested
  one. `tocsin doctor` reports the same compatibility judgement via
  `osv.version_compatibility()`, so a host with a different osv-scanner
  release shows the mismatch without running a scan.

## Official documentation

- Project docs: https://google.github.io/osv-scanner/
- Offline mode: `docs/offline-mode.md` in google/osv-scanner
  (https://github.com/google/osv-scanner/blob/main/docs/offline-mode.md)
- CLI usage: `docs/usage.md` in google/osv-scanner
  (https://github.com/google/osv-scanner/blob/main/docs/usage.md)

## Flags used, and why

Invocation shape: `osv-scanner scan source --recursive [--offline] --no-resolve --format json <path>`

| Flag | Why |
|---|---|
| `scan source` | The manifest/lockfile scanning subcommand (not the container/SBOM ones). |
| `--recursive` | Find manifests anywhere under the requested path, not just at its root. |
| `--offline` | Only present in offline mode; disables all network access, including database fetches. Never combined with `--download-offline-databases` -- Tocsin never fetches an offline database itself; the caller supplies one via `--osv-database`. |
| `--no-resolve` | Disables dependency resolution. Without it, a bare `requirements.txt` triggers Python dependency resolution (confirmed empirically: attempting a resolve on `requests==2.19.0`/`urllib3==1.24.1` produced `resolution impossible: requirements conflict: urllib3: "==1.24.1,<1.24,>=1.21.1"` and stopped the whole extraction) -- resolution is exactly the kind of build-adjacent operation Tocsin's global constraints forbid ("No project builds, install hooks, or dependency installation"). |
| `--format json` | The only format this adapter parses. |

Never passed: `--download-offline-databases` (would fetch over the network
during what the caller asked to be an offline check).

## Offline database contract

- There is **no CLI flag** to point at a database directory. It is
  controlled entirely by the environment variable
  `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`.
- `--osv-database PATH` (Tocsin's CLI flag) maps to
  `extra_env={'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY': str(PATH)}` passed to
  the bounded runner; `run_command` only inherits `PATH`/`HOME`/`TMPDIR`/`LANG`
  from the parent process otherwise, so this is the only way the child
  process learns the database location.
- Layout created by v2.5.1 under that directory:
  `<dir>/osv-scalibr/<Ecosystem>/all.zip`, e.g. `<dir>/osv-scalibr/PyPI/all.zip`.
  (Some upstream docs still describe `<dir>/osv-scanner/<ecosystem>/all.zip`;
  the actual v2.5.1 binary writes and reads `osv-scalibr/`, confirmed by
  inspecting a database it populated.)
- Offline mode with `database=None`, or a `--osv-database` path that does
  not exist or is not a directory, returns `unavailable` **without running
  the engine at all** -- verified by a fake runner in
  `tests/test_osv.py::test_offline_without_database_never_calls_runner`
  (and the equivalents for a missing/non-directory database path) that
  raises if called.

## JSON keys consumed

Top-level: `results` (list, or `null` -- both accepted; anything else is
rejected as an unsupported schema), `experimental_config` (ignored).

Per `results[]` entry: `source.path` (manifest path, used as `manifest:
<path>` evidence and in `manifest_paths`), `packages[]`.

Per `packages[]` entry: `package.name`, `package.version`,
`package.ecosystem` (used for `subject`, KB ecosystem mapping, and
matching against `affected[].package`), `groups[]`, `vulnerabilities[]`.

Per `groups[]` entry: `ids` (vulnerability ids sharing this alias group),
`aliases` (all cross-referenced ids, e.g. CVE/GHSA/PYSEC), `max_severity`
(a bare CVSS score string, e.g. `"7.5"`, or absent/empty -> `severity:
'unknown'`).

Per `vulnerabilities[]` entry (only the first one referenced by each group
that also appears as one of that group's `ids` is consulted for fix
data): `id`, `affected[]` (each with `package.name`/`package.ecosystem`
matched against the outer package, and `ranges[].events[].fixed`, where an
`ECOSYSTEM`-typed range's fixed version is preferred over a `GIT`-typed
range's commit hash for the `upgrade to <fixed>` action text), and
`references[].url` (first 3 taken as evidence).

## Exit-code table and mapping

From `cmd/osv-scanner/internal/cmd/run.go` (main branch) plus empirical
runs of the tested binary:

| rc | Meaning (source) | Tocsin completion |
|---|---|---|
| 0 | success / no vulnerabilities | `complete` (or `complete` + one `unassessed` "no manifests" finding if `results` was null/empty with zero packages) |
| 1 | `ErrVulnerabilitiesFound` | `complete`, with `detected` findings |
| 127 | general error (log handler `HasErrored`) | `unavailable` if stderr contains "no offline version of the OSV database is available" (names the ecosystem(s), parsed from `could not load db for <Ecosystem> ecosystem`); otherwise `error` |
| 128 | `ErrNoPackagesFound` ("No package sources found") | `complete` + one `unassessed` "no manifests" finding, `metadata['manifests'] == 0` |
| 129 | `ErrAPIFailed` | `error` ("OSV API failed") |
| 130 | invalid config | `error` ("invalid osv-scanner config") |
| anything else | -- | `error` |

Never `complete` from a nonzero rc other than 1 or 128. Runner-level
failures (before any rc exists) map like Task 3's Homebrew adapter:
`timeout`/`output-limit`/`cancelled` -> `partial` (best-effort: parse
`stdout` if it happens to still be valid JSON, otherwise empty findings);
`permission` -> `error`; `missing` -> `unavailable`.

Malformed or schema-mismatched JSON with rc 0 or 1 is always `error`,
never `complete` or `partial` -- a nonstandard payload cannot be trusted
just because the process exited cleanly.

## Empirical findings (osv-research.md, reproduced against the real binary)

- Offline, DB missing entirely, manifest present: rc=127, stdout
  `{"results": [], ...}`, stderr `could not load db for PyPI ecosystem:
  ... no offline version of the OSV database is available`. A clean-looking
  empty result at rc 127 is **not** a clean scan.
- Offline, empty directory (no manifests): rc=128, empty stdout, stderr
  `No package sources found`.
- `--allow-no-lockfiles` on an empty directory: rc=0, `"results": null`
  (not `[]`) -- the parser accepts both.
- Offline, DB present, `requirements.txt` (`requests==2.19.0`,
  `urllib3==1.24.1`): rc=1, both packages reported with real vulnerability
  data (10 and 24 raw `vulnerabilities[]` entries respectively, deduplicated
  by OSV-Scanner itself into 5 and 12 `groups[]`).
- Without `--no-resolve`: dependency resolution is attempted and can fail
  outright (`resolution impossible: requirements conflict: urllib3:
  "==1.24.1,<1.24,>=1.21.1"`), or require network access. `--no-resolve`
  is always passed.
- Offline, DB present for PyPI only, an npm `package-lock.json` present:
  rc=127, `results: []`, stderr `could not load db for npm ecosystem ...
  no offline version of the OSV database is available` -- a database
  missing for even one manifest's ecosystem yields **no** packages for
  that manifest and a 127 exit, not a partial result for the others in
  that same run (this is a whole-process exit code, not per-manifest).

## Local integration run

Ran the real tested binary (v2.5.1, at
`/Users/example/tools/osv-scanner`,
not part of this repository) against a scratch `requirements.txt`
containing `requests==2.19.0`, offline, with the populated PyPI-only
offline database at
`/Users/example/osvtest/db`
(also not part of this repository), via
`tests/test_osv.py::test_real_osv_scanner_offline_scan_detects_requests_cve`
(gated on `TOCSIN_OSV_SCANNER`/`TOCSIN_OSV_DB` env vars) and a matching ad
hoc script.

**Run date: 2026-09-08.** Result: `scan_project` returned
`completion == 'complete'` with 5 `detected` findings (the real CVEs
affecting `requests==2.19.0`), `metadata['engine'] == {'name':
'osv-scanner', 'version': '2.5.1'}`, and `report.exit_code([result]) ==
1`, exactly as this contract predicts for an rc=1 run. The pytest
integration test passed:

```
tests/test_osv.py::test_real_osv_scanner_offline_scan_detects_requests_cve PASSED
```
