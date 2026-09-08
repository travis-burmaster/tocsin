"""OSV-Scanner dependency vulnerability adapter.

`scan_project` invokes OSV-Scanner (https://google.github.io/osv-scanner/)
against a project directory and `normalize_osv` turns its `--format json`
output into the shared `CheckResult` vocabulary. The engine contract this
module relies on -- verified flags, offline database env var and layout,
exit codes, and empirical rc/stderr behaviour for OSV-Scanner v2.5.1 -- is
recorded in full in docs/evidence/osv-contract.md (discovery notes in
.superpowers/sdd/2026-09-08-tocsin-implementation/osv-research.md); this
module implements that contract rather than re-deriving it.

This never resolves dependencies or builds anything (`--no-resolve` is
always passed), never downloads an offline database
(`--download-offline-databases` is never passed), and offline mode always
requires a `--osv-database` directory supplied by the caller -- there is
no default database location.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from tocsin.kb import kb_metadata, read_kb
from tocsin.models import CheckResult, Finding, Package, Runner
from tocsin.runner import run_command

_NAME = 'project'

_VERSION_TIMEOUT = 30
_VERSION_MAX_BYTES = 65536
_SCAN_TIMEOUT = 600
_SCAN_MAX_BYTES = 64 * 1024 * 1024  # 64 MiB

# The verified, tested release (docs/evidence/osv-contract.md). Only this
# major.minor is accepted; anything else could carry a different CLI
# contract or JSON schema that this adapter was never checked against.
_TESTED_VERSION = '2.5.1'
_SUPPORTED_MAJOR_MINOR = (2, 5)

_VERSION_LINE_RE = re.compile(r'^osv-scanner version:\s*(\d+)\.(\d+)\.(\d+)', re.MULTILINE)

_NO_OFFLINE_DB_TRIGGER = 'no offline version of the OSV database'
_ECOSYSTEM_FROM_ERROR_RE = re.compile(r'could not load db for (\S+) ecosystem')

# OSV ecosystem name -> Tocsin/KB ecosystem name. Ecosystems not listed
# here are reported as KB-unavailable with a reason rather than guessed at.
_ECOSYSTEM_KB_MAP = {
    'PyPI': 'python',
    'npm': 'npm',
    'crates.io': 'rust',
    'Go': 'go',
    'NuGet': 'dotnet',
}

# Mirrors the mapping Task 3 (platforms/macos.py) uses for the bounded
# runner's failure vocabulary, applied identically to both the version
# guard and the scan invocation.
_RUNNER_FAILURE_TO_COMPLETION = {
    'timeout': 'partial',
    'output-limit': 'partial',
    'cancelled': 'partial',
    'permission': 'error',
}

# Fixed OSV-Scanner exit codes (see docs/evidence/osv-contract.md) that map
# to a fixed error message regardless of stderr content.
_FIXED_ERROR_BY_RC = {
    129: 'OSV API failed',
    130: 'invalid osv-scanner config',
}

_NO_MANIFESTS_ACTION = (
    "no supported dependency manifests detected; coverage is the engine's supported manifest list"
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _parse_version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION_LINE_RE.search(text)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def version_compatibility(version_text: str) -> str:
    """Describe an osv-scanner `--version` output's compatibility.

    Uses the same parser and supported major.minor as `scan_project`'s
    version guard, so `tocsin doctor` reports exactly what a scan would
    decide without duplicating the parsing rule.
    """
    found = _parse_version(version_text)
    if found is None:
        return 'could not parse version (expected an "osv-scanner version: X.Y.Z" line)'
    found_str = '.'.join(str(part) for part in found)
    if found[:2] == _SUPPORTED_MAJOR_MINOR:
        return f'{found_str}, matches tested release {_TESTED_VERSION}'
    return (
        f'{found_str}, tocsin is tested against {_TESTED_VERSION} '
        f'({_SUPPORTED_MAJOR_MINOR[0]}.{_SUPPORTED_MAJOR_MINOR[1]}.x only)'
    )


def _base_metadata(*, kb_root: Path | None, engine: dict[str, object] | None = None,
                    mode: str | None = None, database: str | None = None,
                    command: list[str] | None = None) -> dict[str, object]:
    metadata: dict[str, object] = {
        'packages': 0,
        'packages_with_findings': 0,
        'manifests': 0,
        'manifest_paths': [],
        'packages_kb': {},
        'engine': engine or {'name': 'osv-scanner', 'version': None},
        'mode': mode,
        'database': database,
        'kb': kb_metadata(kb_root),
        'coverage': {'assessed': 0, 'unassessed': 0},
    }
    if command is not None:
        metadata['command'] = command
    return metadata


def _empty_result(*, completion: str, errors: tuple[str, ...], kb_root: Path | None,
                   engine: dict[str, object] | None = None, mode: str | None = None,
                   database: str | None = None, command: list[str] | None = None) -> CheckResult:
    return CheckResult(
        name=_NAME, completion=completion, findings=(), errors=errors,
        metadata=_base_metadata(kb_root=kb_root, engine=engine, mode=mode, database=database, command=command),
    )


def _kb_context_for_osv(ecosystem: str, name: str, version: str, kb_root: Path | None) -> dict[str, object]:
    if kb_root is None:
        return {'status': 'unavailable', 'reason': 'no --kb path supplied'}
    mapped = _ECOSYSTEM_KB_MAP.get(ecosystem)
    if mapped is None:
        return {
            'status': 'unavailable',
            'reason': f'unsupported OSV ecosystem for KB lookup: {ecosystem}',
        }
    return read_kb(kb_root, Package(mapped, name, version, {}))


def _find_fixed_version(vulnerability: dict[str, object], *, name: str, ecosystem: str) -> str | None:
    """Return the version to upgrade to, or None if no fix is recorded.

    Prefers an ECOSYSTEM-typed range's `fixed` event (a plain version
    string, e.g. "2.20.0") over a GIT-typed range's `fixed` event (a
    commit hash) when both are present, since the former is what a
    human upgrade instruction should name.
    """
    ecosystem_fixed: str | None = None
    other_fixed: str | None = None
    for affected in vulnerability.get('affected') or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get('package') or {}
        if not isinstance(package, dict):
            continue
        if str(package.get('name')) != name or str(package.get('ecosystem')) != ecosystem:
            continue
        for value_range in affected.get('ranges') or []:
            if not isinstance(value_range, dict):
                continue
            for event in value_range.get('events') or []:
                if not (isinstance(event, dict) and 'fixed' in event):
                    continue
                fixed = str(event['fixed'])
                if value_range.get('type') == 'ECOSYSTEM' and ecosystem_fixed is None:
                    ecosystem_fixed = fixed
                elif other_fixed is None:
                    other_fixed = fixed
    return ecosystem_fixed or other_fixed


def _package_findings(pkg_entry: dict[str, object], *, manifest_path: str | None,
                       kb_root: Path | None, observed_at: str,
                       packages_kb: dict[str, object]) -> list[Finding]:
    package = pkg_entry.get('package') or {}
    if not isinstance(package, dict):
        return []
    name = str(package.get('name', ''))
    version = str(package.get('version', ''))
    ecosystem = str(package.get('ecosystem', ''))

    vulnerabilities = pkg_entry.get('vulnerabilities') or []
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return []

    groups = pkg_entry.get('groups') or []
    if not isinstance(groups, list):
        groups = []

    vulns_by_id = {
        v['id']: v for v in vulnerabilities if isinstance(v, dict) and 'id' in v
    }

    first_vuln = vulnerabilities[0] if isinstance(vulnerabilities[0], dict) else {}
    reference_urls: list[str] = []
    for reference in (first_vuln.get('references') or [])[:3]:
        if isinstance(reference, dict) and reference.get('url'):
            reference_urls.append(str(reference['url']))

    subject = f'{name} {version} ({ecosystem})'

    kb_key = f'{ecosystem}:{name}:{version}'
    kb_context = _kb_context_for_osv(ecosystem, name, version, kb_root)
    packages_kb[kb_key] = kb_context
    kb_source_url = kb_context.get('source_url') if kb_context.get('status') == 'found' else None

    findings: list[Finding] = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        group_ids = [str(gid) for gid in (group.get('ids') or [])]
        # "aliases (deduplicated)": drop aliases already present as a group
        # id so the same identifier is not repeated twice in evidence.
        group_aliases = [
            str(alias) for alias in dict.fromkeys(group.get('aliases') or [])
            if str(alias) not in group_ids
        ]
        max_severity = group.get('max_severity')
        severity = str(max_severity) if max_severity else 'unknown'

        representative_vuln = None
        for group_id in group_ids:
            if group_id in vulns_by_id:
                representative_vuln = vulns_by_id[group_id]
                break

        action = 'review advisory'
        if representative_vuln is not None:
            fixed = _find_fixed_version(representative_vuln, name=name, ecosystem=ecosystem)
            if fixed is not None:
                action = f'upgrade to {fixed}'

        manifest_label = manifest_path if manifest_path is not None else '(unknown manifest)'
        evidence: list[str] = list(group_ids) + group_aliases
        evidence.append(f'manifest: {manifest_label}')
        evidence.extend(reference_urls)
        if kb_source_url:
            evidence.append(kb_source_url)

        findings.append(Finding(
            category='dependency',
            subject=subject,
            status='detected',
            severity=severity,
            confidence='high',
            evidence=tuple(evidence),
            action=action,
            observed_at=observed_at,
        ))
    return findings


def _normalize_payload(payload: str, *, kb_root: Path | None, observed_at: str) -> CheckResult:
    """Parse `osv-scanner ... --format json` output into a CheckResult.

    Pure function of the payload text: knows nothing about exit codes,
    the scanned project path, or invocation metadata (mode, database,
    command, engine version) -- `scan_project` layers those on. In
    particular this never emits the "no supported manifests" finding,
    because building its subject (the project path) requires information
    this function does not have.
    """
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        return CheckResult(
            name=_NAME, completion='error', findings=(),
            errors=(f'could not parse osv-scanner output: {exc}',),
            metadata=_base_metadata(kb_root=kb_root),
        )

    if not isinstance(data, dict) or 'results' not in data:
        return CheckResult(
            name=_NAME, completion='error', findings=(),
            errors=('unsupported osv-scanner output schema',),
            metadata=_base_metadata(kb_root=kb_root),
        )

    results = data.get('results')
    if results is None:
        results = []
    if not isinstance(results, list):
        return CheckResult(
            name=_NAME, completion='error', findings=(),
            errors=('unsupported osv-scanner output schema',),
            metadata=_base_metadata(kb_root=kb_root),
        )

    findings: list[Finding] = []
    manifest_paths: list[str] = []
    packages_kb: dict[str, object] = {}
    total_packages = 0
    packages_with_findings = 0

    for entry in results:
        if not isinstance(entry, dict):
            continue
        source = entry.get('source')
        manifest_path = source.get('path') if isinstance(source, dict) else None
        if manifest_path:
            manifest_paths.append(str(manifest_path))

        packages = entry.get('packages')
        if not isinstance(packages, list):
            continue
        for pkg_entry in packages:
            if not isinstance(pkg_entry, dict):
                continue
            total_packages += 1
            vulnerabilities = pkg_entry.get('vulnerabilities') or []
            if isinstance(vulnerabilities, list) and vulnerabilities:
                packages_with_findings += 1
                findings.extend(_package_findings(
                    pkg_entry, manifest_path=manifest_path, kb_root=kb_root,
                    observed_at=observed_at, packages_kb=packages_kb,
                ))

    metadata: dict[str, object] = {
        'packages': total_packages,
        'packages_with_findings': packages_with_findings,
        'manifests': len(results),
        'manifest_paths': manifest_paths,
        'packages_kb': packages_kb,
        'kb': kb_metadata(kb_root),
        'coverage': {'assessed': total_packages, 'unassessed': 0},
    }
    return CheckResult(name=_NAME, completion='complete', findings=tuple(findings), errors=(), metadata=metadata)


def normalize_osv(payload: str) -> CheckResult:
    """Parse `osv-scanner ... --format json` output with no KB context.

    Equivalent to what `scan_project` does internally, but without a KB
    root (matching the shape Task 3's KB-less checks report) and without
    the exit-code-driven "no supported manifests" finding, which needs
    the scanned project path that this function is not given.
    """
    return _normalize_payload(payload, kb_root=None, observed_at=_now_iso())


def _augment_metadata(metadata: dict[str, object], *, engine: dict[str, object], mode: str,
                       database: str | None, command: list[str]) -> dict[str, object]:
    augmented = dict(metadata)
    augmented['engine'] = engine
    augmented['mode'] = mode
    augmented['database'] = database
    augmented['command'] = command
    return augmented


def _with_no_manifests_finding(result: CheckResult, *, path: Path, observed_at: str) -> CheckResult:
    finding = Finding(
        category='dependency',
        subject=str(path),
        status='unassessed',
        severity='unknown',
        confidence='high',
        evidence=(),
        action=_NO_MANIFESTS_ACTION,
        observed_at=observed_at,
    )
    metadata = dict(result.metadata)
    metadata['coverage'] = {'assessed': 0, 'unassessed': 1}
    return CheckResult(
        name=result.name, completion='complete', findings=(finding,),
        errors=result.errors, metadata=metadata,
    )


def scan_project(path: Path, *, online: bool, database: Path | None,
                  kb_root: Path | None = None, runner: Runner = run_command) -> CheckResult:
    """Check a project's dependency manifests for known vulnerabilities.

    Runs OSV-Scanner (`scan source --recursive --no-resolve --format
    json`) against `path`. Online lookups only happen when `online` is
    explicitly True; otherwise `database` must name a local offline
    database directory (passed via the engine's
    `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` env var -- see
    docs/evidence/osv-contract.md), or this returns `unavailable` without
    running the engine at all.
    """
    observed_at = _now_iso()
    path = Path(path).resolve()

    osv_path = shutil.which('osv-scanner')
    if osv_path is None:
        return _empty_result(
            completion='unavailable',
            errors=('osv-scanner not found on PATH',),
            kb_root=kb_root,
        )

    if not online:
        if database is None:
            return _empty_result(
                completion='unavailable',
                errors=('offline dependency checks need --osv-database PATH (or --online)',),
                kb_root=kb_root,
            )
        database = Path(database)
        if not database.is_dir():
            return _empty_result(
                completion='unavailable',
                errors=(f'--osv-database path does not exist or is not a directory: {database}',),
                kb_root=kb_root,
            )

    version_argv = [osv_path, '--version']
    version_result = runner(version_argv, timeout=_VERSION_TIMEOUT, max_bytes=_VERSION_MAX_BYTES)
    if version_result.failure == 'missing':
        return _empty_result(
            completion='unavailable',
            errors=('osv-scanner not found on PATH',),
            kb_root=kb_root, command=version_argv,
        )
    if version_result.failure is not None:
        completion = _RUNNER_FAILURE_TO_COMPLETION.get(version_result.failure, 'error')
        return _empty_result(
            completion=completion,
            errors=(f'osv-scanner --version did not complete: {version_result.failure}',),
            kb_root=kb_root, command=version_argv,
        )

    found_version = _parse_version(version_result.stdout) or _parse_version(version_result.stderr)
    if found_version is None or found_version[:2] != _SUPPORTED_MAJOR_MINOR:
        found_str = '.'.join(str(part) for part in found_version) if found_version else '(unparseable version output)'
        return _empty_result(
            completion='unavailable',
            errors=(
                f'osv-scanner version {found_str} found on PATH; tocsin is tested against '
                f'{_TESTED_VERSION} ({_SUPPORTED_MAJOR_MINOR[0]}.{_SUPPORTED_MAJOR_MINOR[1]}.x only)',
            ),
            kb_root=kb_root, command=version_argv,
        )
    engine_version = '.'.join(str(part) for part in found_version)
    engine_meta = {'name': 'osv-scanner', 'version': engine_version}
    mode = 'online' if online else 'offline'
    database_str = str(database) if database is not None else None

    argv = [osv_path, 'scan', 'source', '--recursive']
    extra_env: dict[str, str] | None = None
    if not online:
        argv.append('--offline')
        extra_env = {'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY': database_str}
    argv.extend(['--no-resolve', '--format', 'json', str(path)])

    result = runner(argv, timeout=_SCAN_TIMEOUT, max_bytes=_SCAN_MAX_BYTES, extra_env=extra_env)

    if result.failure == 'missing':
        return _empty_result(
            completion='unavailable',
            errors=('osv-scanner not found on PATH',),
            kb_root=kb_root, engine=engine_meta, mode=mode, database=database_str, command=argv,
        )
    if result.failure is not None:
        completion = _RUNNER_FAILURE_TO_COMPLETION.get(result.failure, 'error')
        findings: tuple[Finding, ...] = ()
        metadata = _base_metadata(kb_root=kb_root)
        if completion == 'partial':
            # Best-effort: a truncated/killed run's stdout is rarely valid
            # JSON, but if it happens to be complete, surface what it found
            # rather than discarding it.
            partial = _normalize_payload(result.stdout, kb_root=kb_root, observed_at=observed_at)
            if partial.completion != 'error':
                findings = partial.findings
                metadata = dict(partial.metadata)
        return CheckResult(
            name=_NAME, completion=completion, findings=findings,
            errors=(f'osv-scanner did not complete: {result.failure}',),
            metadata=_augment_metadata(metadata, engine=engine_meta, mode=mode, database=database_str, command=argv),
        )

    rc = result.returncode
    stderr = result.stderr

    if rc in (0, 1):
        parsed = _normalize_payload(result.stdout, kb_root=kb_root, observed_at=observed_at)
        metadata = _augment_metadata(parsed.metadata, engine=engine_meta, mode=mode, database=database_str, command=argv)
        if parsed.completion == 'error':
            return CheckResult(name=_NAME, completion='error', findings=(), errors=parsed.errors, metadata=metadata)
        base_result = CheckResult(name=_NAME, completion='complete', findings=parsed.findings, errors=(), metadata=metadata)
        if parsed.metadata.get('manifests') == 0:
            return _with_no_manifests_finding(base_result, path=path, observed_at=observed_at)
        return base_result

    if rc == 128:
        # ErrNoPackagesFound: no supported manifest was found at all.
        metadata = _augment_metadata(
            _base_metadata(kb_root=kb_root), engine=engine_meta, mode=mode, database=database_str, command=argv,
        )
        base_result = CheckResult(name=_NAME, completion='complete', findings=(), errors=(), metadata=metadata)
        return _with_no_manifests_finding(base_result, path=path, observed_at=observed_at)

    metadata = _augment_metadata(
        _base_metadata(kb_root=kb_root), engine=engine_meta, mode=mode, database=database_str, command=argv,
    )

    if rc == 127:
        if _NO_OFFLINE_DB_TRIGGER in stderr:
            ecosystems = sorted(dict.fromkeys(_ECOSYSTEM_FROM_ERROR_RE.findall(stderr)))
            names = ', '.join(ecosystems) if ecosystems else '(ecosystem not named in stderr)'
            return CheckResult(
                name=_NAME, completion='unavailable', findings=(),
                errors=(f'no offline OSV database available for: {names}',),
                metadata=metadata,
            )
        detail = stderr.strip() or '(no stderr)'
        return CheckResult(
            name=_NAME, completion='error', findings=(),
            errors=(f'osv-scanner exited 127: {detail}',),
            metadata=metadata,
        )

    if rc in _FIXED_ERROR_BY_RC:
        return CheckResult(
            name=_NAME, completion='error', findings=(),
            errors=(_FIXED_ERROR_BY_RC[rc],),
            metadata=metadata,
        )

    detail = stderr.strip() or '(no stderr)'
    return CheckResult(
        name=_NAME, completion='error', findings=(),
        errors=(f'osv-scanner exited {rc}: {detail}',),
        metadata=metadata,
    )
