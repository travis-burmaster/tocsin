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
| 1 | `ErrVulnerabilitiesFound` | `complete`, with `detected` findings -- `partial` instead if stderr also names a per-manifest extraction failure (see below) or if a supplied `--kb` root is unreadable |
| 127 | general error (log handler `HasErrored`) | `unavailable` if stderr contains "no offline version of the OSV database is available" (names the ecosystem(s), parsed from `could not load db for <Ecosystem> ecosystem`); `partial` if `results` is non-empty (handled identically to rc 0/1 above -- not observed against the real binary, see below); otherwise `error` |
| 128 | `ErrNoPackagesFound` ("No package sources found") | `complete` + one `unassessed` "no manifests" finding, `metadata['manifests'] == 0` (`partial` instead if a supplied `--kb` root is unreadable) |
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
just because the process exited cleanly. Any nested value inside a
parseable payload that isn't the expected type (e.g. an `id` that's a
list instead of a string) is individually skipped or coerced rather than
raising; the specific malformed entry is named in `errors` and the run is
downgraded to `partial`. A catch-all wraps the whole parse, so any shape
those per-field guards miss still comes back as `error` with the
exception text instead of an uncaught exception reaching the CLI.

### Per-manifest extraction failures (one broken manifest among several)

A single corrupt manifest does not fail the whole run: osv-scanner logs
one `Error during extraction: ...` line to stderr per broken manifest and
continues with the others. Confirmed against the real v2.5.1 binary with a
`requirements.txt` (`requests==2.19.0`) alongside a corrupt
`package-lock.json` (literal contents `{not json`), offline, PyPI-only DB:

```
$ osv-scanner scan source --recursive --offline --no-resolve --format json <dir>
rc=1
stdout: {"results": [{"source": {"path": ".../requirements.txt", ...}, "packages": [...]}], ...}
       (1 result, the requirements.txt manifest with its usual requests findings;
        package-lock.json does not appear anywhere in `results`)
stderr (relevant line):
Error during extraction: (extracting as javascript/packagelockjson) path/to/package-lock.json:
could not extract: invalid character 'n' looking for beginning of object key string
```

Two more variants were run to map the rc/results relationship precisely:

- Same corrupt `package-lock.json` alone (no other manifest): rc=**128**,
  **empty** stdout (not even a JSON object), stderr has the same
  `Error during extraction` line plus `No package sources found,
  --help for usage information.`.
- The corrupt `package-lock.json` alongside a **clean** `requirements.txt`
  (`requests==2.33.0`, no known vulnerabilities in the test DB): rc=**127**,
  stdout `{"results": [], ...}` (**empty** -- the clean manifest is not
  listed at all, matching the general rule that `results` only lists
  manifests with actual findings), stderr has the same extraction-error
  line with no other cause.

**Conclusion, and where this adapter's spec deviates from the original
hypothesis:** the exit-code priority in this binary is `ErrVulnerabilitiesFound`
(1) over the general `HasErrored` (127) -- if vulnerabilities are found
*anywhere* in the run, rc is 1 even when another manifest also failed to
extract; rc=127 is only reached when nothing found a vulnerability, and in
that case `results` was empty in every configuration tried here. So "an rc
127 run with non-empty results" was not reproducible against this binary;
the adapter still implements that exact case defensively (falls through
to the same handling as rc 0/1), in case a future release changes this
priority, but the behaviour that actually matters in practice is: **rc 0
or 1 with a stderr `Error during extraction` line** downgrades the run to
`partial`, keeps every finding from the manifest(s) that did parse, and
adds one `error`-status `Finding` per extraction-failure line (`subject`
is the manifest filename parsed out of the line when present, else the
bounded raw line itself; the bounded stderr tail is also recorded in
`errors`). An rc=127 run with **empty** `results` keeps the original
mapping unchanged (unavailable/error, per the table above) since there is
nothing parseable to preserve.

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
`/Users/example/osvtest/tools/osv-scanner`,
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

**Re-run date: 2026-09-08 (review fix pass).** Re-ran the same integration
test after the hardening/exit-code fixes described above (`git log` shows
this as the "fix: harden OSV normalization and align KB handling with
inventory" commit); same result: `PASSED`, `completion == 'complete'`,
`detected` findings present, `report.exit_code([result]) == 1`. The
mixed-manifest (valid + corrupt lockfile) observations in the
"Per-manifest extraction failures" section above were captured in this
same pass, directly against the real binary and PyPI-only offline
database (not via the gated pytest test, since that test only exercises
the single-manifest case; the mixed-manifest behavior is covered by fake
runners in `tests/test_osv.py` using the real stderr text captured here).
