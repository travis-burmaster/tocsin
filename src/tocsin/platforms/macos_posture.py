"""macOS security posture and startup review.

`scan_posture` reads five documented macOS security settings (Gatekeeper,
SIP, FileVault, the application firewall, and its stealth mode) through
the bounded runner, and separately inventories launch-time plists under
the user and system `LaunchAgents`/`LaunchDaemons` directories (excluding
`/System/Library`) without ever executing anything they reference.
`parse_setting` maps one command's exit code and output to
enabled/disabled/unknown. See docs/evidence/posture-contract.md (research
notes in .superpowers/sdd/2026-09-08-tocsin-implementation/posture-research.md)
for the exact recognized command-output phrases and the review-signal
rules this module implements.
"""

from __future__ import annotations

import platform
import plistlib
from pathlib import Path

from tocsin.adapters.clamav import _escape_control_chars
from tocsin.models import CheckResult, Finding, Runner
from tocsin.platforms.macos import _now_iso
from tocsin.runner import run_command

# --- macOS security posture and startup review ------------------------------

_POSTURE_NAME = 'posture'

_SETTING_TIMEOUT = 30
_SETTING_MAX_BYTES = 65536

# Absolute paths only: never rely on PATH for these system tools.
_SETTING_COMMANDS: dict[str, list[str]] = {
    'gatekeeper': ['/usr/sbin/spctl', '--status'],
    'sip': ['/usr/bin/csrutil', 'status'],
    'filevault': ['/usr/bin/fdesetup', 'status'],
    'firewall': ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'],
    'firewall_stealth': ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getstealthmode'],
}

_SETTING_ORDER = ('gatekeeper', 'sip', 'filevault', 'firewall', 'firewall_stealth')

_SETTING_DISPLAY_NAMES = {
    'gatekeeper': 'Gatekeeper',
    'sip': 'System Integrity Protection (SIP)',
    'filevault': 'FileVault',
    'firewall': 'Firewall',
    'firewall_stealth': 'Firewall stealth mode',
}

# Recognized command-output phrases, captured read-only on the reference
# Mac (macOS 26.6.2 build 25G83, arm64) -- see posture-research.md and
# docs/evidence/posture-contract.md. Matched as substrings of the first
# non-empty output line, case-sensitively, only when the command exited 0.
# Anything else -- nonzero exit, empty output, changed or unrecognized
# wording (including csrutil's "Custom Configuration" and any future
# deprecation notice) -- is 'unknown' rather than guessed.
_RECOGNIZED_PHRASES: dict[str, dict[str, str]] = {
    'gatekeeper': {
        'assessments enabled': 'enabled',
        'assessments disabled': 'disabled',
    },
    'sip': {
        'System Integrity Protection status: enabled.': 'enabled',
        'System Integrity Protection status: disabled.': 'disabled',
    },
    'filevault': {
        'FileVault is On.': 'enabled',
        'FileVault is Off.': 'disabled',
    },
    'firewall': {
        'Firewall is enabled. (State = 1)': 'enabled',
        'Firewall is enabled. (State = 2)': 'enabled',
        'Firewall is disabled. (State = 0)': 'disabled',
    },
    'firewall_stealth': {
        'Firewall stealth mode is on': 'enabled',
        'Firewall stealth mode is off': 'disabled',
    },
}

# Launch-directory scope: user and system LaunchAgents/LaunchDaemons only.
# /System/Library/LaunchAgents and /System/Library/LaunchDaemons are
# deliberately excluded (Apple-signed volume; see posture-research.md) --
# this is a documented limitation, not exhaustive persistence detection.
_MAX_PLIST_BYTES = 1024 * 1024  # 1 MiB

# /var and /tmp are themselves symlinks to /private/var and /private/tmp
# on macOS, so both the symlinked and the resolved forms are listed.
_UNSAFE_LOCATION_PREFIXES = (
    '/tmp/', '/private/tmp/', '/var/tmp/', '/private/var/tmp/', '/Users/Shared/',
)


def _default_launch_dirs() -> list[Path]:
    return [
        Path.home() / 'Library' / 'LaunchAgents',
        Path('/Library/LaunchAgents'),
        Path('/Library/LaunchDaemons'),
    ]


def _first_nonempty_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ''


def parse_setting(name: str, returncode: int, output: str) -> str:
    """Map one posture command's exit code and output to enabled/disabled/unknown.

    Recognizes only the exact phrases in `_RECOGNIZED_PHRASES` for `name`,
    matched against the *entire* first non-empty line of `output` after
    stripping its leading/trailing whitespace (case-sensitive, exact
    equality -- not a substring match), and only when `returncode == 0`.
    Everything else -- a nonzero exit, a setting with no recognized-phrase
    table, extra text before or after the phrase on that line (e.g. a
    "Note: " prefix or a trailing "(deprecated)"/"(Custom Configuration)"
    suffix), or wording that matches neither the enabled nor the disabled
    phrase -- is 'unknown'. A phrase that only appears on a later line
    (e.g. csrutil's trailing "Configuration:" line) is never matched:
    only the first non-empty line is judged.
    """
    if returncode != 0:
        return 'unknown'
    phrases = _RECOGNIZED_PHRASES.get(name)
    if not phrases:
        return 'unknown'
    first_line = _first_nonempty_line(output)
    for phrase, state in phrases.items():
        if phrase == first_line:
            return state
    return 'unknown'


def _setting_finding(name: str, argv: list[str], result, observed_at: str) -> tuple[Finding, str, bool]:
    """Build the Finding for one posture setting.

    Returns (finding, state, made_partial). `made_partial` is True only
    for a runner failure other than 'missing' (a coverage gap on its own
    does not make the check partial; a runner failure other than a simply
    absent executable does).
    """
    rc = result.returncode
    raw_first_line = _escape_control_chars(_first_nonempty_line(result.stdout))
    evidence = [f"command: {' '.join(argv)}", f'rc: {rc}', raw_first_line]

    made_partial = False
    if result.failure is not None:
        state = 'unknown'
        if result.failure == 'missing':
            reason = 'executable not found'
        elif result.failure == 'permission':
            reason = 'permission denied'
            made_partial = True
        elif result.failure == 'timeout':
            reason = 'command timed out'
            made_partial = True
        else:
            reason = f'command did not complete: {result.failure}'
            made_partial = True
        evidence.append(f'reason: {reason}')
    else:
        state = parse_setting(name, rc, result.stdout)

    display = _SETTING_DISPLAY_NAMES[name]
    if state == 'enabled':
        finding = Finding(
            category='posture', subject=name, status='no-known-match', severity='unknown',
            confidence='high', evidence=tuple(evidence), action='none', observed_at=observed_at,
        )
    elif state == 'disabled':
        finding = Finding(
            category='posture', subject=name, status='needs-review', severity='unknown',
            confidence='high', evidence=tuple(evidence),
            action=f'{display} is disabled; enable it unless there is a documented reason',
            observed_at=observed_at,
        )
    else:
        finding = Finding(
            category='posture', subject=name, status='unassessed', severity='unknown',
            confidence='low', evidence=tuple(evidence),
            action='could not determine; inspect manually', observed_at=observed_at,
        )
    return finding, state, made_partial


def _unsafe_location(executable: str) -> str | None:
    """The matched unsafe-writable-location prefix for `executable`, or None."""
    for prefix in _UNSAFE_LOCATION_PREFIXES:
        if executable.startswith(prefix):
            return prefix
    try:
        downloads_prefix = str(Path.home() / 'Downloads') + '/'
    except RuntimeError:
        return None
    if executable.startswith(downloads_prefix):
        return downloads_prefix
    return None


def _classify_startup_executable(executable: str | None) -> tuple[str, str, tuple[str, ...]]:
    """Classify one launch item's executable into (status, action, extra_evidence).

    Absence of a code signature is never checked here and never a
    finding on its own -- only the three documented signals below (a
    missing referenced executable, an unsafe writable location, or a
    relative path) yield 'needs-review'; everything else is an inventory
    record ('no-known-match'), not a verdict.
    """
    if executable is None:
        return 'no-known-match', 'none', ()
    if executable.startswith('/'):
        # Checked before existence: a program staged under a writable,
        # unsafe location is a signal regardless of whether it happens to
        # exist yet.
        matched = _unsafe_location(executable)
        if matched is not None:
            return (
                'needs-review',
                'executable resolves under a writable, unsafe location',
                (f'unsafe location matched: {matched}',),
            )
        path_obj = Path(executable)
        try:
            missing = not path_obj.exists()
        except PermissionError:
            # Existence could not be determined -- treat as unknown, not missing.
            missing = False
        if missing:
            return (
                'needs-review',
                'referenced executable is missing; verify the launch item is legitimate',
                (),
            )
        return 'no-known-match', 'none', ()
    return 'needs-review', 'relative executable path depends on PATH', ()


def _plist_evidence(plist_path: Path, plist: dict, extra_evidence: tuple[str, ...]) -> tuple[str, ...]:
    evidence = [f'plist: {plist_path}']
    evidence.extend(extra_evidence)
    for key in ('RunAtLoad', 'KeepAlive', 'StartInterval', 'Disabled'):
        if key not in plist:
            continue
        value = plist[key]
        if isinstance(value, bool):
            evidence.append(f'{key}: {"true" if value else "false"}')
        else:
            evidence.append(f'{key}: {value}')
    return tuple(evidence)


def _malformed_plist_finding(plist_path: Path, reason: str, observed_at: str) -> Finding:
    return Finding(
        category='startup', subject=str(plist_path), status='skipped', severity='unknown',
        confidence='high', evidence=(reason,),
        action='plist could not be parsed; inspect manually', observed_at=observed_at,
    )


def _process_plist(plist_path: Path, observed_at: str) -> tuple[Finding, bool]:
    """Read and classify one launch-item plist. Never executes anything it
    references. Returns (finding, skipped): `skipped` is True only when
    the plist itself could not be read or parsed (oversized, unreadable,
    or malformed) -- a coverage gap distinct from a normal review signal.
    """
    try:
        size = plist_path.stat().st_size
    except OSError as exc:
        return _malformed_plist_finding(plist_path, f'could not stat plist: {exc}', observed_at), True

    if size > _MAX_PLIST_BYTES:
        return (
            _malformed_plist_finding(
                plist_path, f'plist exceeds the {_MAX_PLIST_BYTES}-byte bounded-read limit ({size} bytes)', observed_at,
            ),
            True,
        )

    try:
        data = plist_path.read_bytes()
    except OSError as exc:
        return _malformed_plist_finding(plist_path, f'could not read plist: {exc}', observed_at), True

    try:
        plist = plistlib.loads(data)
    except Exception as exc:  # plistlib raises several exception types for malformed input
        return _malformed_plist_finding(plist_path, f'could not parse plist: {exc}', observed_at), True

    if not isinstance(plist, dict):
        return (
            _malformed_plist_finding(plist_path, 'plist top-level value is not a dictionary', observed_at),
            True,
        )

    label = plist.get('Label')
    label_or_filename = label if isinstance(label, str) and label else plist_path.name

    program = plist.get('Program')
    program_args = plist.get('ProgramArguments')
    executable: str | None = None
    if isinstance(program, str) and program:
        executable = program
    elif isinstance(program_args, list) and program_args and isinstance(program_args[0], str) and program_args[0]:
        executable = program_args[0]

    status, action, extra_evidence = _classify_startup_executable(executable)
    confidence = 'medium' if status == 'no-known-match' else 'high'
    subject = f"{label_or_filename}: {executable if executable is not None else '(none)'}"

    finding = Finding(
        category='startup', subject=subject, status=status, severity='unknown',
        confidence=confidence, evidence=_plist_evidence(plist_path, plist, extra_evidence),
        action=action, observed_at=observed_at,
    )
    return finding, False


def _scan_launch_dir(directory: Path, observed_at: str) -> tuple[dict[str, object], list[Finding], list[str], bool]:
    """Inventory one launch directory. Returns (dir_metadata, findings, errors, made_partial)."""
    dir_str = str(directory)
    try:
        exists = directory.exists()
    except OSError as exc:
        # Path.exists() itself can raise (e.g. EACCES/EPERM statting an
        # unsearchable parent, or a TCC-restricted path under
        # ~/Library) -- Path.exists() only swallows ENOENT/ENOTDIR/
        # EBADF/ELOOP internally, so this is an access problem, not
        # "missing": degrade to partial rather than letting it propagate.
        return (
            {'status': 'denied', 'plists': 0, 'symlinks_skipped': 0},
            [],
            [f'could not check {dir_str}: {exc}'],
            True,
        )
    if not exists:
        return {'status': 'missing', 'plists': 0, 'symlinks_skipped': 0}, [], [], False

    try:
        entries = sorted(directory.iterdir())
    except NotADirectoryError as exc:
        # The configured path exists but is not a directory (e.g. a plain
        # file) -- a misconfiguration, not an access problem, so it gets
        # its own status, but is still a partial inventory with an error.
        return (
            {'status': 'unreadable', 'plists': 0, 'symlinks_skipped': 0},
            [],
            [f'{dir_str} is not a directory: {exc}'],
            True,
        )
    except OSError as exc:
        # Widened from PermissionError alone: any other OSError iterdir()
        # can raise (including a PermissionError with a different errno
        # than plain EACCES) must degrade to partial, never propagate.
        return (
            {'status': 'denied', 'plists': 0, 'symlinks_skipped': 0},
            [],
            [f'permission denied listing {dir_str}: {exc}'],
            True,
        )

    findings: list[Finding] = []
    plist_count = 0
    symlinks_skipped = 0
    made_partial = False

    for entry in entries:
        try:
            is_link = entry.is_symlink()
        except OSError:
            is_link = False
        if is_link:
            symlinks_skipped += 1
            continue
        try:
            is_regular = entry.is_file()
        except OSError:
            is_regular = False
        if not is_regular or entry.suffix != '.plist':
            continue

        plist_count += 1
        finding, skipped = _process_plist(entry, observed_at)
        findings.append(finding)
        if skipped:
            made_partial = True

    metadata = {'status': 'read', 'plists': plist_count, 'symlinks_skipped': symlinks_skipped}
    return metadata, findings, [], made_partial


def scan_posture(*, runner: Runner = run_command, launch_dirs: list[Path] | None = None,
                  observed_at: str | None = None) -> CheckResult:
    """Check macOS security posture (Gatekeeper/SIP/FileVault/firewall) and
    inventory user + system launch-time plists.

    Never alters any setting and never executes anything a launch-item
    plist references -- see the module docstring and
    docs/evidence/posture-contract.md. `launch_dirs` defaults to
    `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and
    `/Library/LaunchDaemons`; `/System/Library/*` is out of scope (a
    documented limitation, not an oversight), and this inventory is never
    a claim of exhaustive persistence detection. `observed_at` defaults to
    the current UTC time when omitted; the CLI passes one run timestamp
    shared by every adapter it calls.
    """
    if observed_at is None:
        observed_at = _now_iso()
    if launch_dirs is None:
        launch_dirs = _default_launch_dirs()

    findings: list[Finding] = []
    errors: list[str] = []
    commands: list[list[str]] = []
    settings_meta: dict[str, dict[str, object]] = {}
    setting_failures: list[str | None] = []
    made_partial = False

    assessed_settings = 0
    unknown_settings = 0

    for name in _SETTING_ORDER:
        argv = _SETTING_COMMANDS[name]
        commands.append(argv)
        result = runner(argv, timeout=_SETTING_TIMEOUT, max_bytes=_SETTING_MAX_BYTES)
        setting_failures.append(result.failure)

        finding, state, setting_made_partial = _setting_finding(name, argv, result, observed_at)
        findings.append(finding)
        made_partial = made_partial or setting_made_partial

        settings_meta[name] = {
            'state': state,
            'rc': result.returncode,
            'raw_first_line': _escape_control_chars(_first_nonempty_line(result.stdout)),
        }
        if state == 'unknown':
            unknown_settings += 1
            # A simply absent executable ('missing') is an expected,
            # non-partial coverage gap, not an operational error; only a
            # failure that actually stopped the check running (permission,
            # timeout, ...) is worth surfacing in `errors`.
            if result.failure is not None and result.failure != 'missing':
                errors.append(f"{name} check ({' '.join(argv)}) did not complete: {result.failure}")
        else:
            assessed_settings += 1

    launch_dirs_meta: dict[str, dict[str, object]] = {}
    startup_reviewed = 0
    plists_skipped = 0
    startup_items = 0

    for directory in launch_dirs:
        dir_metadata, dir_findings, dir_errors, dir_made_partial = _scan_launch_dir(directory, observed_at)
        launch_dirs_meta[str(directory)] = dir_metadata
        findings.extend(dir_findings)
        errors.extend(dir_errors)
        made_partial = made_partial or dir_made_partial
        startup_items += int(dir_metadata.get('plists', 0))
        for finding in dir_findings:
            if finding.status == 'skipped':
                plists_skipped += 1
            else:
                startup_reviewed += 1

    all_permission_denied = (
        len(setting_failures) == len(_SETTING_ORDER)
        and all(failure == 'permission' for failure in setting_failures)
    )

    if all_permission_denied:
        completion = 'error'
    elif made_partial:
        completion = 'partial'
    else:
        completion = 'complete'

    host = {
        'system': platform.system(),
        'release': platform.mac_ver()[0] or None,
        'machine': platform.machine(),
    }
    limitations = [
        '/System/Library/LaunchAgents and /System/Library/LaunchDaemons are excluded from this inventory.',
        'This launch-item inventory is not exhaustive persistence detection.',
        'Settings are read from documented CLI wording only; unrecognized or changed wording is reported as unknown rather than guessed.',
    ]

    metadata: dict[str, object] = {
        'settings': settings_meta,
        'launch_dirs': launch_dirs_meta,
        'startup_items': startup_items,
        'commands': commands,
        'host': host,
        'limitations': limitations,
        'coverage': {
            'assessed': assessed_settings + startup_reviewed,
            'unassessed': unknown_settings + plists_skipped,
        },
    }

    return CheckResult(
        name=_POSTURE_NAME, completion=completion, findings=tuple(findings),
        errors=tuple(errors), metadata=metadata,
    )
