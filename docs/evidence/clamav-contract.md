# ClamAV (clamscan) engine contract (evidence)

Adapter: `src/tocsin/adapters/clamav.py`. This records the exact engine
contract the adapter implements, so any future change to how Tocsin
invokes clamscan is a deliberate, re-verified decision rather than an
assumption.

## No live engine on the development host

**clamscan is not installed on the machine this task was implemented on,
and it was not installed for this task** (global constraint: no project
builds, install hooks, or dependency installation; the research notes for
this task were also explicit that clamscan must not be installed on this
Mac). Every test in `tests/test_clamav.py` therefore runs against an
injected fake `Runner` and fixture text under `tests/fixtures/clamav/`
(`help.txt`, `help_missing_alert_exceeds_max.txt`, `version.txt`,
`version_garbage.txt`), never a real subprocess.

`tests/test_clamav.py::test_real_clamscan_detects_eicar` is written as an
optional, environment-gated integration test: it only runs when
`TOCSIN_CLAMSCAN` is set to a real clamscan binary path backed by a
working signature database. It was **not run** during this task, because
no such binary was available. It writes the standard EICAR test string
(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
into a file under pytest's `tmp_path` (never anywhere else, and never
distributed), scans it, and asserts a `detected` finding. Anyone with a
real clamscan install can verify the adapter end-to-end by running:

```
TOCSIN_CLAMSCAN=/path/to/clamscan .venv/bin/python -m pytest tests/test_clamav.py -k real_clamscan -q
```

## Source

- `clamscan.1` man page, Cisco-Talos/clamav main branch, verified
  2026-09-08 (see
  `.superpowers/sdd/2026-09-08-tocsin-implementation/clamav-research.md`
  for the raw research notes this section summarizes).

## Return codes

- `0`: no virus found.
- `1`: virus(es) found.
- `2`: some error(s) occurred.

`scan_files` maps these as follows (see "Exit-code handling" below for the
full, ordered decision).

## Flags used, and why

Invocation shape:

```
clamscan --stdout --infected --alert-exceeds-max=yes --alert-encrypted=yes \
  --max-filesize=100M --max-scansize=500M --max-recursion=20 \
  --follow-dir-symlinks=0 --follow-file-symlinks=0 --file-list=<tempfile>
```

| Flag | Why |
|---|---|
| `--stdout` | Sends alert/summary output to stdout instead of stderr, so the bounded runner's single combined byte budget behaves predictably and matches what `--infected` output actually contains. |
| `--infected` | Only infected/alerted files are printed (`OK` lines are suppressed). Captured output then scales with the number of alerts, not with the number of files scanned -- the runner's `max_bytes` budget is a cap on alert volume, not a hidden cap on how large a tree can be scanned. |
| `--alert-exceeds-max=yes` | Without this, a file or container member that exceeds `--max-filesize`/`--max-scansize`/`--max-recursion` is silently treated as clean (an `OK`/no-alert result). With it, such a file is reported as a `Heuristics.Limits.Exceeded.*` alert instead. This is why the feature guard treats a clamscan lacking this flag as `unavailable`: without it, oversized content -- including a deliberately oversized payload meant to evade scanning -- could be reported clean. |
| `--alert-encrypted=yes` | Same reasoning for encrypted archives/documents (`.zip`, `.7z`, `.rar`, `.pdf`, ...): without it, an encrypted container ClamAV cannot look inside is scanned as if it were empty and reported clean. With it, ClamAV reports `Heuristics.Encrypted.*` instead. |
| `--max-filesize=100M` | Per-file scan size cap. Reported in metadata `limits`. |
| `--max-scansize=500M` | Total expanded data scanned per container (upstream default is 400M; Tocsin passes 500M explicitly per this project's decided limit). |
| `--max-recursion=20` | Archive/container recursion depth cap (upstream default 17, max 100). |
| `--follow-dir-symlinks=0` / `--follow-file-symlinks=0` | Never follow symlinks, matching Tocsin's own enumeration (see below) -- a symlink pointing outside the requested root must never smuggle content into the scan. |
| `--file-list=<tempfile>` | The list of absolute paths to scan, one per line (see "File enumeration and `--file-list`" below). |

**Never passed:** `--recursive` (Tocsin enumerates files itself; see
below), `--remove`, `--move`, `--copy` (Tocsin never modifies or moves
scanned files -- a `detected` finding's action explicitly says to
quarantine or delete only after manual confirmation), `--database`
(Tocsin never supplies or downloads a database; whatever database the
installed clamscan already has configured is used as-is, and no
signature fetch is ever triggered by this adapter).

## File enumeration and `--file-list`, and why

Tocsin enumerates files itself, rather than pointing clamscan at a
directory with `--recursive`:

- Resolve the requested path to absolute.
- If it is a regular file, scan just that file.
- If it is a directory, walk it with `os.walk(path, followlinks=False)`.
  `followlinks=False` stops `os.walk` from *recursing into* a symlinked
  directory, but a symlinked directory or file is still *listed* at the
  level it appears in -- so the adapter additionally checks
  `Path.is_symlink()` on every directory and file entry itself and skips
  it (counting it in metadata `symlinks_skipped`) rather than relying on
  `os.walk`'s behavior alone.
- Only regular files (confirmed with `os.lstat` + `stat.S_ISREG`, not a
  followed stat) are included as scan candidates.
- Enumeration is capped at 100,000 files (`_MAX_FILES`); beyond that,
  enumeration stops and the result is `partial` with an error naming the
  cap.
- A candidate file whose absolute path contains a control character
  (`\x00`-`\x1f`, `\x7f` -- this includes a literal newline) or the
  two-character sequence `": "` is **not** scanned: `clamscan`'s
  plain-text alert line format is `<path>: <name> FOUND`, and either of
  these makes a line unsplittable/ambiguous (a newline could be mistaken
  for a line boundary; a `": "` inside the path could be mistaken for the
  path/verdict separator). Such a file gets a `skipped` Finding (subject:
  the path with control characters escaped as `\xHH`; action: rename and
  rescan) and the whole check becomes `partial`.
- A file that vanishes or becomes unreadable during the enumeration
  `stat()` call also gets a `skipped` Finding and `partial`.
- The remaining accepted absolute paths are written one per line to a
  temp file created via `tempfile.mkstemp()` and explicitly `chmod`ed to
  `0600`, passed as `--file-list=<path>`, and removed in a `finally`
  block regardless of how the scan call completes.

This design means clamscan never receives a positional path argument at
all -- every `argv` element after the binary path is a flag -- and never
walks anything on its own; Tocsin's own enumeration is the single source
of truth for what gets scanned.

**Documented limitation:** a file can be replaced (same path, different
content) between Tocsin's enumeration `stat()` and the moment clamscan
actually reads it. Tocsin does not detect or protect against this
TOCTOU-style race; a result naming a path is a report about what
clamscan actually read at scan time, not a cryptographic attestation tied
to the enumeration-time file identity. Because of this (and more broadly,
because Tocsin never modifies files), the adapter never offers automatic
remediation based on a path-only result -- every `detected` finding's
action says to quarantine or delete only after manual confirmation.

## Output line format assumed, and the ambiguity rule

With `--infected --stdout`, stdout carries only alert lines and the final
summary block (no per-file `OK` lines).

- Alert line: `<absolute path>: <name> FOUND`. Because ambiguous paths
  (control character or `": "`) were excluded before scanning, every
  requested path is guaranteed not to contain `": "` or a control
  character, so each alert line is parsed with `line[:-len(' FOUND')]`
  followed by `rsplit(': ', 1)` to recover `(path, name)` unambiguously.
- **Ambiguity rule:** a parsed `path` is only trusted if it exactly
  matches one of the paths Tocsin actually submitted via `--file-list`.
  A `FOUND` line naming any other path is treated as parse ambiguity: it
  is discarded and recorded as a plain string in `errors` (never
  silently trusted, never turned into a Finding), and the run becomes
  `partial`.
- Limit/encryption alerts: `Heuristics.Limits.Exceeded.MaxFileSize`,
  `.MaxScanSize`, `.MaxRecursion`, `.MaxFiles`; `Heuristics.Encrypted.Zip`,
  `.PDF`, etc. -- all mapped to `skipped` Findings (evidence: the alert
  name; action: "file exceeded scan limits or is encrypted; inspect
  manually").
- Any other `Heuristics.*` alert -> `needs-review` (severity `unknown`,
  confidence `medium`): a heuristic guess, not a confirmed signature.
- Any other alert name (e.g. `Eicar-Signature`, a real malware signature
  name) -> `detected` (severity `unknown` because ClamAV does not emit
  one; confidence `high`; evidence: the signature name; action:
  "quarantine or delete only after manual confirmation; Tocsin does not
  modify files").
- Summary block: parsed for `Known viruses:`, `Engine version:`,
  `Scanned files:`, `Infected files:`, `Data scanned:`, `Data read:`,
  `Time:` into metadata `summary`, with `None` for any key not present in
  the output. `files_scanned` in top-level metadata is `int(Scanned
  files)` when parseable, else `None`.
- stderr lines containing `Can't open file`, `Access denied`,
  `LibClamAV Error`, or `ERROR:` are recorded as plain strings in
  `errors` (bounded to 50 lines of at most 500 characters each) and force
  `partial` -- clamscan emits these as diagnostic text, not per-file
  structured alerts, so there is nothing to turn into a Finding.

## Limits (verified against the man page; see clamav-research.md)

| Limit | Value | Upstream default |
|---|---|---|
| `--max-filesize` | 100M | 100 MB (upstream default) |
| `--max-scansize` | 500M | 400 MB (Tocsin's project decision overrides the default) |
| `--max-recursion` | 20 | 17 (upstream default) |
| operation timeout | 300 seconds | n/a (Tocsin's own bound via the runner) |
| enumeration cap | 100,000 files | n/a (Tocsin's own bound; upstream `--max-files` default is 10,000 but that flag limits scanning *inside a single container*, not the number of top-level files Tocsin submits) |

All of these are surfaced verbatim in `CheckResult.metadata['limits']`.

## Exit-code handling (the full, ordered decision `scan_files` implements)

Runner failures (before any clamscan exit code exists) are handled first,
identically to the OSV-Scanner and Homebrew adapters' failure-kind
mapping:

- `missing` -> `unavailable` (should not happen here in practice, since
  `shutil.which('clamscan')` is already checked before ever invoking the
  scan, but handled defensively).
- `timeout` / `output-limit` / `cancelled` -> `partial`, keeping whatever
  alert lines were parsed from the captured stdout **prefix**: if the
  captured text does not end with a newline, the final (possibly
  mid-write) line is dropped before parsing, so a truncated alert line is
  never misparsed into a wrong or partial path/name.
- `permission` -> `error`.

Once a real exit code exists:

- `rc == 0`: `complete` (no detections), **unless** enumeration produced
  any ambiguous/stat-error/cap-exceeded findings, or this scan's own
  output produced any `skipped` findings or `errors` -- any of those
  downgrade it to `partial`.
- `rc == 1`: `complete` with detections/heuristics, subject to the same
  downgrade-to-`partial` conditions above. `detected`/`needs-review`
  findings alone never make a result `partial` (the shared `CheckResult`
  invariant only forces non-`complete` for `error`/`skipped` findings).
- `rc == 2` **and no `FOUND` line was parsed at all** (e.g. clamscan's own
  named example, `CommandResult(2, '', 'database unavailable', None)`):
  `error`, with **zero findings** -- this is the one case where Tocsin
  never invents a clean or `no-known-match`-flavored result out of a
  failed run. `no-known-match` is never emitted by this adapter under any
  circumstances.
- `rc == 2` **with at least one parsed `FOUND` line**: the parsed alerts
  are kept, and completion is `partial` (something clearly went wrong
  during the run, but whatever clamscan did manage to report is still
  surfaced rather than discarded).
- Any other `rc`: `error`, with the raw stderr detail (or a placeholder)
  in `errors`.

## Feature detection instead of a version pin

Every other adapter in this project (OSV-Scanner, Homebrew) pins a tested
engine version because a real binary was available to verify against. No
clamscan binary was available anywhere in this environment for Task 6,
so there was nothing to pin a version against. Instead:

1. `shutil.which('clamscan')` absent -> `unavailable`, and **no command is
   ever run** (not even `--version`).
2. `clamscan --version` is run (timeout 30s, 64 KiB budget) and parsed as
   `ClamAV <engine>/<sigdb>/<sig date>` (e.g. `ClamAV
   1.4.2/27540/Tue Feb 11 09:22:11 2025`) into metadata `engine =
   {'name': 'clamav', 'version', 'signature_version', 'signature_date'}`.
   Any part of the line that doesn't match this shape parses as all three
   fields `None` rather than raising or guessing.
3. `clamscan --help` is run (timeout 30s, 256 KiB budget) and checked for
   every flag this adapter passes. `--alert-exceeds-max` is checked
   first and named specifically if missing (`'installed clamscan lacks
   --alert-exceeds-max; oversized content could be reported clean'`),
   because that flag is the one whose absence has a silent-false-negative
   consequence. Any other missing required flag also makes the check
   `unavailable`, naming the specific flag.

`tocsin doctor` calls the exact same probe (`clamav.doctor_summary`) so
its report of clamscan's presence, engine/signature version and date, and
required-flag support matches what a `--files` scan would actually decide
-- there is no separate, potentially-diverging doctor-only check.

## Official documentation

- clamscan(1) man page: https://docs.clamav.net/manual/Usage/Scanning.html
- ClamAV source (flags/behavior cross-referenced): https://github.com/Cisco-Talos/clamav
