"""Homebrew package inventory and macOS security posture, enriched with
local KB context where applicable.

`parse_brew` turns `brew info --json=v2 --installed` output into the
shared `Package` vocabulary. `inventory_brew` runs that command through
the bounded runner, parses it, and produces a `CheckResult` carrying
whatever KB context is available. Every package is an `unassessed`
finding except curl, which `tocsin.adapters.curl.assess_curl` evaluates
against a reviewed advisory snapshot -- the first (and so far only)
Homebrew formula with real vulnerability coverage; everything else has
no reviewed advisory adapter yet.

`scan_posture` reads five documented macOS security settings (Gatekeeper,
SIP, FileVault, the application firewall, and its stealth mode) through
the bounded runner, and separately inventories launch-time plists under
the user and system `LaunchAgents`/`LaunchDaemons` directories (excluding
`/System/Library`) without ever executing anything they reference. See
docs/evidence/posture-contract.md (research notes in
.superpowers/sdd/2026-09-08-tocsin-implementation/posture-research.md)
for the exact recognized command-output phrases and the review-signal
rules this module implements.
"""

from __future__ import annotations

import json
import platform
import plistlib
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from tocsin.adapters.clamav import _escape_control_chars
from tocsin.adapters.curl import assess_curl, load_records
from tocsin.kb import kb_metadata as _kb_metadata
from tocsin.kb import kb_unreadable_reason as _kb_unreadable_reason
from tocsin.kb import read_kb
from tocsin.models import CheckResult, Finding, Package, Runner
from tocsin.runner import run_command

_BREW_TIMEOUT = 120
_BREW_MAX_BYTES = 16 * 1024 * 1024  # 16 MiB
_BREW_EXTRA_ENV = {'HOMEBREW_NO_AUTO_UPDATE': '1'}

_CORE_TAP = 'homebrew/core'

# Splits a Homebrew revision suffix, e.g. "8.0.0_1" -> version "8.0.0",
# revision "1", so downstream matchers never see the underscore form.
_REVISION_SUFFIX_RE = re.compile(r'^(?P<version>.+)_(?P<revision>\d+)$')

_RUNNER_FAILURE_TO_COMPLETION = {
    'timeout': 'partial',
    'output-limit': 'partial',
    'cancelled': 'partial',
    'permission': 'error',
}


def _split_revision(raw_version: str) -> tuple[str, str | None]:
    match = _REVISION_SUFFIX_RE.match(raw_version)
    if match:
        return match.group('version'), match.group('revision')
    return raw_version, None


def _formula_packages(formula: dict[str, object]) -> list[Package]:
    name = str(formula.get('name', ''))
    full_name = formula.get('full_name')
    tap = formula.get('tap')
    formula_revision = formula.get('revision')

    installed = formula.get('installed') or []
    if not isinstance(installed, list):
        raise ValueError(
            f'brew JSON formula "installed" must be a list, got {type(installed).__name__}'
        )

    packages: list[Package] = []
    for entry in installed:
        if not isinstance(entry, dict):
            raise ValueError('brew JSON formula "installed" entries must be objects')
        raw_version = str(entry.get('version', ''))
        version, suffix_revision = _split_revision(raw_version)

        provenance: dict[str, str] = {'kind': 'formula'}
        if full_name is not None:
            provenance['full_name'] = str(full_name)
        if tap is not None:
            provenance['tap'] = str(tap)
        if suffix_revision is not None:
            provenance['revision'] = suffix_revision
        elif formula_revision is not None:
            provenance['revision'] = str(formula_revision)
        if 'installed_as_dependency' in entry:
            provenance['installed_as_dependency'] = str(bool(entry['installed_as_dependency'])).lower()
        if 'installed_on_request' in entry:
            provenance['installed_on_request'] = str(bool(entry['installed_on_request'])).lower()
        for arch_key in ('architecture', 'arch'):
            if arch_key in entry:
                provenance['architecture'] = str(entry[arch_key])
                break

        packages.append(Package('homebrew', name, version, provenance))
    return packages


def _cask_packages(cask: dict[str, object]) -> list[Package]:
    token = str(cask.get('token', ''))
    full_token = cask.get('full_token')
    tap = cask.get('tap')
    installed_version = cask.get('installed')
    if installed_version is None:
        return []  # listed but not actually installed

    provenance: dict[str, str] = {'kind': 'cask'}
    if full_token is not None:
        provenance['full_name'] = str(full_token)
    if tap is not None:
        provenance['tap'] = str(tap)

    return [Package('homebrew-cask', token, str(installed_version), provenance)]


def parse_brew(payload: str) -> list[Package]:
    """Parse `brew info --json=v2 --installed` output into Packages.

    One Package per entry in a formula's `installed` list (so a formula
    with two installed versions yields two Packages); casks yield one
    Package each from their single `installed` version. Raises
    `json.JSONDecodeError` on unparseable input, and `ValueError` on
    input that is valid JSON but the wrong shape (not an object, or a
    "formulae"/"casks"/"installed" entry that isn't the list-of-objects
    the v2 schema promises) -- callers decide how that maps onto a
    CheckResult's completion.
    """
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError(f'brew JSON payload must be an object, got {type(data).__name__}')

    packages: list[Package] = []

    formulae = data.get('formulae', [])
    if not isinstance(formulae, list):
        raise ValueError(f'brew JSON "formulae" must be a list, got {type(formulae).__name__}')
    for formula in formulae:
        if not isinstance(formula, dict):
            raise ValueError('brew JSON formula entries must be objects')
        packages.extend(_formula_packages(formula))

    casks = data.get('casks', [])
    if not isinstance(casks, list):
        raise ValueError(f'brew JSON "casks" must be a list, got {type(casks).__name__}')
    for cask in casks:
        if not isinstance(cask, dict):
            raise ValueError('brew JSON cask entries must be objects')
        packages.extend(_cask_packages(cask))

    return packages


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _kb_context_for(package: Package, kb_root: Path | None) -> dict[str, object]:
    if kb_root is None:
        return {'status': 'unavailable', 'reason': 'no --kb path supplied'}
    if package.ecosystem == 'homebrew':
        tap = package.provenance.get('tap')
        if tap is None:
            # A formula installed from a local .rb file or a URL has no
            # tap at all -- never treat that as core by default.
            return {
                'status': 'unavailable',
                'reason': (
                    f'formula has an untapped or unknown tap; KB lookup is '
                    f'limited to {_CORE_TAP}'
                ),
            }
        if tap != _CORE_TAP:
            return {
                'status': 'unavailable',
                'reason': f'tap-qualified formula ({tap}); KB lookup is limited to {_CORE_TAP}',
            }
    return read_kb(kb_root, package)


def _empty_result(*, completion: str, errors: tuple[str, ...], kb_root: Path | None,
                   command: list[str] | None = None) -> CheckResult:
    metadata: dict[str, object] = {
        'packages': [],
        'kb': _kb_metadata(kb_root),
        'coverage': {'assessed': 0, 'unassessed': 0},
    }
    if command is not None:
        metadata['command'] = command
    return CheckResult(name='brew', completion=completion, findings=(), errors=errors, metadata=metadata)


def inventory_brew(*, kb_root: Path | None = None, runner: Runner = run_command) -> CheckResult:
    """Inventory installed Homebrew formulae and casks, with KB context.

    Every package becomes an `unassessed` Finding: no reviewed advisory
    adapter exists for Homebrew formulae yet, so this never reports a
    clean or vulnerable verdict, only coverage. `completion` reflects
    whether the inventory itself succeeded, not whether every package was
    assessed for vulnerabilities.
    """
    observed_at = _now_iso()

    brew_path = shutil.which('brew')
    if brew_path is None:
        return _empty_result(
            completion='unavailable',
            errors=('Homebrew (`brew`) was not found on PATH',),
            kb_root=kb_root,
        )

    argv = [brew_path, 'info', '--json=v2', '--installed']
    result = runner(argv, timeout=_BREW_TIMEOUT, max_bytes=_BREW_MAX_BYTES, extra_env=_BREW_EXTRA_ENV)

    if result.failure == 'missing':
        return _empty_result(
            completion='unavailable',
            errors=('Homebrew (`brew`) was not found on PATH',),
            kb_root=kb_root,
            command=argv,
        )
    if result.failure is not None:
        completion = _RUNNER_FAILURE_TO_COMPLETION.get(result.failure, 'error')
        return _empty_result(
            completion=completion,
            errors=(f'brew info --json=v2 --installed did not complete: {result.failure}',),
            kb_root=kb_root,
            command=argv,
        )
    if result.returncode != 0:
        detail = result.stderr.strip() or '(no stderr)'
        return _empty_result(
            completion='error',
            errors=(f'brew info --json=v2 --installed exited {result.returncode}: {detail}',),
            kb_root=kb_root,
            command=argv,
        )

    try:
        packages = parse_brew(result.stdout)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError, AttributeError) as exc:
        # ValueError/AttributeError are a backstop: parse_brew shape-checks
        # every level it descends into and raises ValueError itself, but
        # this still catches anything an unanticipated JSON shape could
        # trigger rather than letting it escape as an unhandled crash.
        return _empty_result(
            completion='error',
            errors=(f'could not parse brew info --json=v2 --installed output: {exc}',),
            kb_root=kb_root,
            command=argv,
        )

    kb_metadata = _kb_metadata(kb_root)
    kb_unreadable_reason = _kb_unreadable_reason(kb_metadata)

    findings: list[Finding] = []
    serialized_packages: list[dict[str, object]] = []

    # curl is the first (and so far only) Homebrew formula with a reviewed
    # advisory adapter (Task 5); every other formula stays unassessed. The
    # snapshot is loaded at most once per inventory run and reused for every
    # curl Package (a formula can have more than one "installed" entry).
    # If loading fails (corrupt or malformed snapshot file), curl falls
    # back to the generic unassessed finding and the failure is surfaced
    # in `errors`, downgrading completion to partial rather than silently
    # losing curl's coverage or crashing the whole inventory.
    curl_records: list[dict] | None = None
    curl_load_error: str | None = None
    curl_load_attempted = False
    curl_assessment_metadata: dict[str, object] | None = None
    assessed_count = 0

    for package in packages:
        if kb_unreadable_reason is not None:
            # --kb was given but the path itself is unusable: the
            # inventory still succeeded, but no package can get real KB
            # context, regardless of tap or ecosystem.
            context: dict[str, object] = {'status': 'unavailable', 'reason': kb_unreadable_reason}
        else:
            context = _kb_context_for(package, kb_root)

        is_curl = package.ecosystem == 'homebrew' and package.name == 'curl'
        if is_curl and not curl_load_attempted:
            curl_load_attempted = True
            try:
                curl_records = load_records()
            except (OSError, ValueError) as exc:
                curl_load_error = f'could not load curl advisory snapshot: {exc}'

        if is_curl and curl_records is not None:
            curl_result = assess_curl(package, curl_records, observed_at=observed_at)
            findings.extend(curl_result.findings)
            curl_assessment_metadata = curl_result.metadata
            assessed_count += 1
        else:
            subject = f'{package.name} {package.version}'
            is_cask = package.ecosystem == 'homebrew-cask'
            action = (
                'casks are outside initial vulnerability coverage'
                if is_cask
                else 'no reviewed advisory adapter for this formula'
            )
            evidence: tuple[str, ...] = ()
            source_url = context.get('source_url') if context.get('status') == 'found' else None
            if source_url:
                evidence = (source_url,)

            findings.append(Finding(
                category='package',
                subject=subject,
                status='unassessed',
                severity='unknown',
                confidence='high',
                evidence=evidence,
                action=action,
                observed_at=observed_at,
            ))

        serialized_packages.append({
            'ecosystem': package.ecosystem,
            'name': package.name,
            'version': package.version,
            'provenance': dict(package.provenance),
            'kb': context,
        })

    errors: list[str] = []
    completion = 'complete'
    if kb_unreadable_reason is not None:
        # The inventory itself completed; only the requested KB context
        # could not be attached, so this is partial, not an error.
        errors.append(kb_unreadable_reason)
        completion = 'partial'
    if curl_load_error is not None:
        errors.append(curl_load_error)
        completion = 'partial'

    metadata: dict[str, object] = {
        'packages': serialized_packages,
        'kb': kb_metadata,
        'coverage': {'assessed': assessed_count, 'unassessed': len(packages) - assessed_count},
        'command': argv,
    }
    if curl_assessment_metadata is not None:
        metadata['assessments'] = {'curl': curl_assessment_metadata}

    return CheckResult(
        name='brew', completion=completion, findings=tuple(findings),
        errors=tuple(errors), metadata=metadata,
    )


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

_UNSAFE_LOCATION_PREFIXES = ('/tmp/', '/private/tmp/', '/var/tmp/', '/Users/Shared/')


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
    matched as a substring of the first non-empty line of `output`
    (case-sensitive, leading/trailing whitespace on that line ignored),
    and only when `returncode == 0`. Everything else -- a nonzero exit, a
    setting with no recognized-phrase table, or wording that matches
    neither the enabled nor the disabled phrase -- is 'unknown'. A phrase
    that only appears on a later line (e.g. csrutil's trailing
    "Configuration:" line) is never matched: only the first non-empty
    line is judged.
    """
    if returncode != 0:
        return 'unknown'
    phrases = _RECOGNIZED_PHRASES.get(name)
    if not phrases:
        return 'unknown'
    first_line = _first_nonempty_line(output)
    for phrase, state in phrases.items():
        if phrase in first_line:
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
    if not directory.exists():
        return {'status': 'missing', 'plists': 0, 'symlinks_skipped': 0}, [], [], False

    try:
        entries = sorted(directory.iterdir())
    except PermissionError:
        return (
            {'status': 'denied', 'plists': 0, 'symlinks_skipped': 0},
            [],
            [f'permission denied listing {dir_str}'],
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


def scan_posture(*, runner: Runner = run_command, launch_dirs: list[Path] | None = None) -> CheckResult:
    """Check macOS security posture (Gatekeeper/SIP/FileVault/firewall) and
    inventory user + system launch-time plists.

    Never alters any setting and never executes anything a launch-item
    plist references -- see the module docstring and
    docs/evidence/posture-contract.md. `launch_dirs` defaults to
    `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and
    `/Library/LaunchDaemons`; `/System/Library/*` is out of scope (a
    documented limitation, not an oversight), and this inventory is never
    a claim of exhaustive persistence detection.
    """
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
