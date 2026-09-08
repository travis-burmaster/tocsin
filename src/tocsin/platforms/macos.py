"""Homebrew package inventory, enriched with local KB context.

`parse_brew` turns `brew info --json=v2 --installed` output into the
shared `Package` vocabulary. `inventory_brew` runs that command through
the bounded runner, parses it, and produces a `CheckResult` where every
package is an `unassessed` finding (no reviewed advisory adapter exists
for Homebrew formulae yet -- Task 5 adds one for curl) carrying whatever
KB context is available.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from tocsin.kb import kb_snapshot, read_kb
from tocsin.models import CheckResult, Finding, Package, Runner
from tocsin.runner import run_command

_BREW_TIMEOUT = 120
_BREW_MAX_BYTES = 16 * 1024 * 1024  # 16 MiB
_BREW_EXTRA_ENV = {'HOMEBREW_NO_AUTO_UPDATE': '1'}

_CORE_TAP = 'homebrew/core'

# Attribution for the OSS Security KB, attached once per report (not per
# package) in metadata['kb'] whenever a readable KB checkout is in use.
_KB_LICENSE = 'CC BY 4.0'
_KB_LICENSE_URL = 'https://github.com/travis-burmaster/oss-security-kb/blob/main/LICENSE'
_KB_SOURCE = 'https://github.com/travis-burmaster/oss-security-kb'
_KB_MAINTAINER = 'Travis Burmaster'

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


def _kb_metadata(kb_root: Path | None) -> dict[str, object]:
    """Build the once-per-report metadata['kb'] entry, in a single shape.

    'unavailable' when no --kb was supplied at all; 'unreadable' when a
    path was supplied but does not exist or is not a directory; else
    'available', carrying the KB snapshot identity plus attribution
    (license, source, maintainer) so it is preserved wherever this
    report ends up, per the KB's attribution requirements.
    """
    if kb_root is None:
        return {'status': 'unavailable', 'reason': 'no --kb path supplied'}
    kb_root = Path(kb_root)
    if not kb_root.is_dir():
        return {
            'status': 'unreadable',
            'root': str(kb_root),
            'reason': f'--kb path does not exist or is not a directory: {kb_root}',
        }
    snapshot = kb_snapshot(kb_root)
    return {
        'status': 'available',
        'root': snapshot.get('root'),
        'commit': snapshot.get('commit'),
        'dirty': snapshot.get('dirty'),
        'license': _KB_LICENSE,
        'license_url': _KB_LICENSE_URL,
        'source': _KB_SOURCE,
        'maintainer': _KB_MAINTAINER,
    }


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
    kb_unreadable_reason = kb_metadata.get('reason') if kb_metadata.get('status') == 'unreadable' else None

    findings: list[Finding] = []
    serialized_packages: list[dict[str, object]] = []
    for package in packages:
        if kb_unreadable_reason is not None:
            # --kb was given but the path itself is unusable: the
            # inventory still succeeded, but no package can get real KB
            # context, regardless of tap or ecosystem.
            context: dict[str, object] = {'status': 'unavailable', 'reason': kb_unreadable_reason}
        else:
            context = _kb_context_for(package, kb_root)
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

    metadata: dict[str, object] = {
        'packages': serialized_packages,
        'kb': kb_metadata,
        'coverage': {'assessed': 0, 'unassessed': len(packages)},
        'command': argv,
    }

    if kb_unreadable_reason is not None:
        # The inventory itself completed; only the requested KB context
        # could not be attached, so this is partial, not an error.
        return CheckResult(
            name='brew', completion='partial', findings=tuple(findings),
            errors=(kb_unreadable_reason,), metadata=metadata,
        )

    return CheckResult(name='brew', completion='complete', findings=tuple(findings), errors=(), metadata=metadata)
