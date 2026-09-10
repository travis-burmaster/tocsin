# ClamAV (clamscan) engine contract (evidence)

Adapter: `src/tocsin/adapters/clamav.py`. This records the exact engine
contract the adapter implements, so any future change to how Tocsin
invokes clamscan is a deliberate, re-verified decision rather than an
assumption.

## Live engine verification (2026-09-10)

A real engine was installed and used to verify this contract:
**ClamAV 1.5.4** (Homebrew bottle `clamav` 1.5.4, `brew install clamav`)
on macOS 26.6.2 (build 25G83), arm64. Signatures were updated with
`freshclam`: `main.cvd` v63 (3,287,027 signatures), `daily.cvd` 28119,
`bytecode.cvd` 339; total known viruses 3,628,058; signature date
Thu Sep 10 00:24:09 2026. `freshclam` needed one extra manual step beyond
`brew install clamav` on this bottle (see "Installing the external
engines" in `docs/development.md`), and printed `ERROR: NULL X509 store`
twice per database while still reporting `Database test passed` for each
and writing the `.cvd.sign` files -- a known Homebrew 1.5 quirk; the
databases were usable despite the error text.

All ten flags this adapter passes were confirmed present in this build's
`clamscan --help` (`--stdout`, `--infected`, `--alert-exceeds-max`,
`--alert-encrypted`, `--max-filesize`, `--max-scansize`,
`--max-recursion`, `--follow-dir-symlinks`, `--follow-file-symlinks`,
`--file-list`) -- the man-page-derived flag list below was not just
theoretical.

`tocsin doctor` reported: `clamscan: engine 1.5.4, signatures 28119
(Thu Sep 10 00:24:09 2026), required flags present`.

### End-to-end scan

`tocsin scan --files <dir with eicar.txt, clean.txt, sub/nested.txt,
enc.zip (a password-protected zip)>`: completion `partial`; findings:
`detected` eicar.txt (evidence `Eicar-Test-Signature`), `skipped`
enc.zip (evidence `Heuristics.Encrypted.Zip`); coverage `assessed=4
unassessed=0`; exit code 2 (partial because of the skipped encrypted
archive). The gated integration test
(`TOCSIN_CLAMSCAN=/opt/homebrew/bin/clamscan .venv/bin/python -m pytest
tests/test_clamav.py -k real_clamscan -q`) passed against this engine,
and the full suite passed with `TOCSIN_CLAMSCAN` set (see
`docs/evidence/validation.md` for the exact counts).

### Raw engine probes (output routing)

Direct `clamscan --stdout --infected --alert-exceeds-max=yes
--alert-encrypted=yes --max-filesize=100K --follow-dir-symlinks=0
--follow-file-symlinks=0 --file-list=...` probes, run outside the
adapter, confirmed:

- **Limit/encrypted alert strings**: a 300 KB file against a 100K
  `--max-filesize` produced `<path>: Heuristics.Limits.Exceeded.MaxFileSize
  FOUND`; a zip produced `<path>: Heuristics.Encrypted.Zip FOUND` -- both
  exactly the strings this adapter's classifier keys on.
- **Missing-file diagnostics appear on BOTH streams** with `--stdout`: a
  `WARNING: <path>: Can't access file` line on stdout, and a plain
  `<path>: No such file or directory` line on stderr.
- **rc precedence: 1 wins when any `FOUND` line exists**, even when
  errors also occurred in the same run -- a file list mixing a
  detection/heuristic alert with a missing file still exits 1, not 2.
- **A permission-denied file produces no per-file diagnostic at all**
  under `--infected` in 1.5.4: scanning only a chmod-000 file yields rc
  2, stdout containing *only* the summary block (`Scanned files: 0`,
  `Total errors: 1`), and empty stderr -- no line naming the file on
  either stream. Before this was handled, Tocsin reported `error` with
  the uninformative message `clamscan exited 2: (no stderr)` and a
  coverage count (`assessed=2`) that did not match the one file the
  engine actually scanned. `src/tocsin/adapters/clamav.py` now parses
  the `Total errors` and `Scanned files` summary lines explicitly:
  an unnamed-error count and the scanned/requested gap are reported as
  explicit `errors` strings instead of "(no stderr)", completion is
  forced to `partial` when this occurs alongside a `FOUND` line or on rc
  0/1, and `metadata['coverage']` is corrected to what the engine
  actually scanned (see `_SUMMARY_KEY_MAP`, `_int_summary_field`, and the
  `total_errors_note`/`scanned_gap_note` handling in `scan_files`).
  **`Total errors` is only printed when N > 0** -- a clean run's summary
  omits the line entirely rather than printing `Total errors: 0` (also
  confirmed against this engine).

`tests/test_clamav.py::test_real_clamscan_detects_eicar`,
`test_real_clamscan_unreadable_file_is_informative_error`, and
`test_real_clamscan_undersized_random_file_not_flagged` are optional,
environment-gated integration tests (`TOCSIN_CLAMSCAN`) that exercise the
above against a real binary; run them with:

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
- A candidate file whose absolute path is not valid UTF-8 (surfaced by
  Python as a string containing a lone surrogate, via `os.fsdecode`'s
  `'surrogateescape'` error handler for a non-UTF-8 byte -- e.g. a
  filename that arrived over SMB/NFS from a filesystem with a different
  encoding) is **also not scanned**, for the same reason: it cannot be
  written into the (UTF-8) file-list at all. Tocsin chose to skip such
  files rather than attempt a lossy surrogateescape round-trip through
  clamscan's own text output, because that output's encoding behavior
  for non-UTF-8 paths could not be verified against a real engine in this
  environment. This is checked by the same `_ambiguity_reason` helper and
  produces the same kind of `skipped` Finding (evidence: `'filename is
  not valid UTF-8'`).
- A file that vanishes or becomes unreadable during the enumeration
  `stat()` call also gets a `skipped` Finding and `partial`.
- The remaining accepted absolute paths are written one per line to a
  temp file created via `tempfile.mkstemp()`. The file descriptor is
  wrapped with `os.fdopen()` *before* `os.fchmod(handle.fileno(), 0o600)`
  is called on it (not `os.chmod()` on the path beforehand): if `fchmod`
  raises, the `with` block still closes the fd, so nothing leaks. The
  path is passed as `--file-list=<path>` and removed in a `finally` block
  regardless of how the scan call completes. Because every path in the
  file list already passed the UTF-8 check above, this write is always
  plain strict-UTF-8 and can never raise `UnicodeEncodeError`.

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
- **Per-file diagnostics print on stdout, not stderr.** `--stdout`
  redirects everything clamscan would otherwise write to stderr -- the
  `--help` text says so explicitly ("Write to stdout instead of stderr")
  and clamav-research.md's output-format notes list `Can't open file` /
  `Access denied` alongside the per-file `OK`/`FOUND` lines. So every
  non-`FOUND`, non-blank, non-summary-block line on stdout is treated as
  a diagnostic: if it names one of the requested paths (clamscan's
  per-file diagnostics take the shape `<path>: <message>`, e.g. `<path>:
  Can't open file`, `<path>: Empty file`) it becomes an error for that
  path even if the message text doesn't match one of the trigger
  substrings below; a line matching a known trigger (`Can't open file`,
  `Access denied`, `LibClamAV Error`, `ERROR:`) is recorded even without
  a recognizable leading path. stderr is scanned the same way for the
  same trigger substrings, in case a build or wrapper still emits
  diagnostics there. All such lines are recorded as plain strings in
  `errors` (bounded to 50 lines of at most 500 characters each) and force
  `partial` -- clamscan does not emit structured per-file objects for
  these, just diagnostic text.

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
  `error`, with **zero PARSED alert findings** -- this is the one case
  where Tocsin never invents a clean or `no-known-match`-flavored result
  out of a failed run. `no-known-match` is never emitted by this adapter
  under any circumstances. Enumeration-time findings (ambiguous/non-UTF-8
  names, stat failures) and errors (including the enumeration-cap
  message) are **not** discarded here, even though the scan attempt
  itself produced nothing usable: the global exit-code policy states
  "exit 2: partial or failed, retaining any findings," and that applies
  to what enumeration already established regardless of how the
  subsequent scan attempt went.
- `rc == 2` **with at least one parsed `FOUND` line**: the parsed alerts
  are kept, and completion is `partial` (something clearly went wrong
  during the run, but whatever clamscan did manage to report is still
  surfaced rather than discarded).
- Any other `rc`: `error`, with the raw stderr detail (or a placeholder)
  in `errors`, alongside the same retained enumeration findings/errors.
- A runner failure of an unrecognized kind (i.e. anything other than
  `missing`/`timeout`/`output-limit`/`cancelled`/`permission`, none of
  which is expected in practice) is also `error` while still retaining
  enumeration findings/errors -- no branch of `scan_files` discards
  enumeration-time evidence just because the scan call itself failed or
  produced nothing.

## Feature detection instead of a version pin

Every other adapter in this project (OSV-Scanner, Homebrew) pins a tested
engine version because a real binary was available to verify against. No
clamscan binary was available anywhere in this environment for Task 6,
so there was nothing to pin a version against at the time. Feature
detection is kept even after the 2026-09-10 live verification against
ClamAV 1.5.4 (see "Live engine verification" above): only that one engine
version on one host has been confirmed, which is not enough evidence to
switch to a version pin the way OSV-Scanner's is. Instead:

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
