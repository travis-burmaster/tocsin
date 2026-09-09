# macOS security posture and startup review contract (evidence)

Adapter: `src/tocsin/platforms/macos.py` (`scan_posture`, `parse_setting`).
This records the exact command outputs, recognized phrases, and
launch-item review rules the adapter implements, so any future change to
what Tocsin trusts as "enabled"/"disabled" or "needs-review" is a
deliberate, re-verified decision rather than an assumption.

## Source

Real command outputs captured read-only on the available Mac (controller,
2026-09-08): **macOS 26.6.2, build 25G83, arm64 (Apple Silicon). Intel was
not tested** -- see
`.superpowers/sdd/2026-09-08-tocsin-implementation/posture-research.md`
for the raw research notes this section summarizes. No setting was
altered to capture these outputs.

## Commands (absolute paths; never rely on PATH)

| Setting | Command | Timeout | Max bytes |
|---|---|---|---|
| `gatekeeper` | `/usr/sbin/spctl --status` | 30s | 65536 |
| `sip` | `/usr/bin/csrutil status` | 30s | 65536 |
| `filevault` | `/usr/bin/fdesetup status` | 30s | 65536 |
| `firewall` | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` | 30s | 65536 |
| `firewall_stealth` | `/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode` | 30s | 65536 |

Every command runs through the bounded runner (`tocsin.runner.run_command`
by default); Tocsin never alters any of these settings and never escalates
privileges to read them.

## Recognized phrases (exact, case-sensitive, first non-empty line only)

`parse_setting(name, returncode, output)` recognizes only the phrases
below, matched as a **substring of the first non-empty line** of
`output`, and only when `returncode == 0`. Anything else -- a nonzero
exit code, empty output, a setting with no phrase table, or wording that
matches neither the enabled nor the disabled phrase (including csrutil's
"Custom Configuration" state, a "Deferred enablement" FileVault message,
or any future deprecation notice) -- is reported as `unknown` rather than
guessed from a partial word like "enabled" alone. A phrase that appears
only on a line after the first is never matched.

| Setting | Enabled phrase (captured sample) | Disabled phrase (captured sample) |
|---|---|---|
| `gatekeeper` | `assessments enabled` | `assessments disabled` |
| `sip` | `System Integrity Protection status: enabled.` | `System Integrity Protection status: disabled.` |
| `filevault` | `FileVault is On.` | `FileVault is Off.` |
| `firewall` | `Firewall is enabled. (State = 1)` or `(State = 2)` | `Firewall is disabled. (State = 0)` |
| `firewall_stealth` | `Firewall stealth mode is on` | `Firewall stealth mode is off` |

## Finding shape per setting

- `enabled` &rarr; `no-known-match` (severity `unknown`, confidence
  `high`, action `none`) -- recorded so the report shows what was
  verified, not silently dropped.
- `disabled` &rarr; `needs-review` (severity `unknown`, confidence
  `high`, action e.g. "Gatekeeper is disabled; enable it unless there is
  a documented reason").
- `unknown` &rarr; `unassessed` (confidence `low`, action "could not
  determine; inspect manually"). A runner failure of `missing` (the
  executable simply is not present) is a coverage gap and does not make
  the check `partial`; `permission`, `timeout`, and any other runner
  failure do.

Evidence always includes `command: <argv joined>`, `rc: <n>`, and the
first non-empty line of raw output (escaped for control characters via
`tocsin.adapters.clamav._escape_control_chars`, reused rather than
re-implemented); a runner failure adds a `reason: ...` evidence line.

Completion is `error` only if every one of the five setting commands
failed specifically with a `permission` runner failure; a mix of
failures, or any `missing`/`timeout`/other failure, degrades to `partial`
(or stays `complete` if only `missing` occurred), never `error`.

## Startup (launch-item) inventory

**Scope**: exactly `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and
`/Library/LaunchDaemons`. `/System/Library/LaunchAgents` and
`/System/Library/LaunchDaemons` are **deliberately excluded** -- on the
research host they held 465 and 422 plists respectively, all on the
Apple-signed system volume, and are out of scope for this task. This is a
documented limitation, not an oversight.

**Per directory**:
- Missing directory &rarr; `status: missing` in metadata, no error (not
  every Mac has all three directories populated).
- Permission denied listing the directory &rarr; `status: denied`, an
  entry in `errors`, and the check is `partial` (a partial inventory, not
  a failure).
- Readable &rarr; every entry is listed; a symlink is skipped and counted
  (`symlinks_skipped`) without being followed; only regular `*.plist`
  files are read, bounded to 1 MiB (`plistlib.load`/`plistlib.loads` on
  the bytes; both binary and XML plists occur in practice). Nothing a
  plist references is ever executed, run, or resolved beyond
  `Path(executable).exists()`.
- A plist that cannot be stat'd, exceeds the 1 MiB bound, cannot be read,
  fails to parse, or does not decode to a dictionary &rarr;
  `Finding(category='startup', status='skipped', subject=<plist path>,
  action='plist could not be parsed; inspect manually')`, and the check
  is `partial`.

**Extracted fields** (when present): `Label`, `Program` or
`ProgramArguments[0]` as the executable, `RunAtLoad`, `KeepAlive`,
`StartInterval`, `Disabled`. `Disabled: true`/`false` (and the other
boolean fields) are recorded verbatim in the Finding's evidence when
present.

## Review-signal rules (in priority order; first match wins)

For a successfully parsed plist, subject is `'<Label or filename>:
<executable>'` (`(none)` when no `Program`/`ProgramArguments[0]` is
present):

1. The executable string is absolute and resolves under a clearly unsafe
   writable location -- any of `/tmp/`, `/private/tmp/`, `/var/tmp/`,
   `/Users/Shared/`, or the current user's `~/Downloads/` &rarr;
   `needs-review`, with the matched location prefix recorded in evidence.
   Checked *before* existence, since a program staged under a writable
   location is a signal whether or not it happens to exist yet.
2. Otherwise, the executable is absolute and `Path(executable).exists()`
   is `False` &rarr; `needs-review`, action "referenced executable is
   missing; verify the launch item is legitimate". If checking existence
   raises `PermissionError`, that is treated as **unknown**, not missing,
   and does not trigger this signal.
3. The executable string is relative (no leading `/`) &rarr;
   `needs-review`, action "relative executable path depends on PATH".
4. Otherwise &rarr; `no-known-match`, confidence `medium`, action `none`
   -- an inventory record, not a verdict.

**Absence of a code signature is never checked and never a finding on
its own.** This inventory is explicitly **not** exhaustive persistence
detection: it only covers three directories via `Program`/
`ProgramArguments`, nothing beyond that (login items, cron, periodic
scripts, and `/System/Library` are all out of scope). Both statements are
also recorded in `metadata['limitations']` on every `scan_posture()`
result.

## Coverage and metadata

`metadata['coverage']['assessed']` counts settings resolved to
`enabled`/`disabled` plus startup items reviewed (any status other than
`skipped`); `['unassessed']` counts settings that stayed `unknown` plus
plists that were `skipped`. `metadata['host']` records
`platform.system()`, `platform.mac_ver()[0]` (or `None`), and
`platform.machine()`.

## Smoke test result (read-only, no setting altered)

Run on the controller Mac, **2026-09-08**, via
`.venv/bin/tocsin scan --posture`:

- Exit code: **2** (the check completed `partial` -- see below -- which
  the exit-code policy maps to 2 regardless of the actionable findings
  also present).
- Settings: `gatekeeper` enabled, `sip` enabled, `filevault` enabled,
  `firewall` **disabled**, `firewall_stealth` **disabled** (two
  `needs-review` findings; three `no-known-match`).
- Launch directories: `~/Library/LaunchAgents` read, 6 plists, 0 symlinks
  skipped; `/Library/LaunchAgents` read, 10 plists, 0 symlinks skipped;
  `/Library/LaunchDaemons` read, 15 plists, 0 symlinks skipped -- matching
  posture-research.md's captured counts exactly.
- Startup items: 31 total. One `needs-review` (a Homebrew-managed launch
  agent whose referenced executable no longer exists on disk); one
  `skipped` (a LaunchDaemon plist owned by another user, permission
  denied on read, which is what made this run's completion `partial`
  rather than `complete`); the remaining items were `no-known-match`.
- Host: `Darwin`, release `26.6.2`, machine `arm64`.
- No plist contents are reproduced here (per instructions); the counts
  above are the full extent of what was recorded from this run.
