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

The engine's JSON output is untrusted input: every nested value consumed
below is type-checked before use (`_as_list`/`_as_dict`/`_hashable_scalar`)
so a hostile or simply buggy payload degrades a run to `partial` (with the
specific malformed entry named in `errors`) rather than raising, and
`_normalize_payload` wraps the whole parse in a catch-all so any shape
these guards miss still comes back as `completion == 'error'` instead of
an uncaught exception reaching the CLI.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from tocsin.kb import kb_metadata, kb_unreadable_reason, read_kb
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

# A per-manifest extraction failure (confirmed against the real v2.5.1
# binary: docs/evidence/osv-contract.md). Not every rc that can carry one
# of these lines also carries usable `results` (see the rc handling
# below), but the line itself always has this shape.
_EXTRACTION_ERROR_LINE_RE = re.compile(r'^.*Error during extraction.*$', re.MULTILINE)
_MANIFEST_FILENAME_IN_LINE_RE = re.compile(
    r'(\S*(?:requirements\.txt|package-lock\.json|Cargo\.lock|go\.sum|go\.mod|'
    r'composer\.lock|Gemfile\.lock|poetry\.lock|Pipfile\.lock|yarn\.lock|'
    r'pom\.xml|pnpm-lock\.yaml))'
)
_MAX_ERROR_LINE_LEN = 500
_MAX_STDERR_TAIL_LEN = 2000

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


# --- small defensive JSON-shape helpers -------------------------------------
#
# osv-scanner's output is untrusted input (a buggy or hostile build could
# emit any JSON shape). Every nested value pulled out of it below goes
# through one of these instead of being used directly, so a wrong type
# degrades gracefully (skipped, coerced, or noted) instead of raising.

def _as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _hashable_scalar(value: object) -> str | None:
    """Coerce a JSON scalar (str/int/float/bool) to str; anything else is None.

    Used everywhere a value is about to become a dict key or a
    deduplication candidate: JSON can put a list or object where a plain
    id/alias is expected, and those are not hashable.
    """
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (str, int, float)):
        return str(value)
    return None


def _base_metadata(*, kb_root: Path | None, engine: dict[str, object] | None = None,
                    mode: str | None = None, database: str | None = None,
                    command: list[str] | None = None, kb_meta: dict[str, object] | None = None) -> dict[str, object]:
    metadata: dict[str, object] = {
        'packages': 0,
        'packages_with_findings': 0,
        'manifests': 0,
        'manifest_paths': [],
        'packages_kb': {},
        'engine': engine or {'name': 'osv-scanner', 'version': None},
        'mode': mode,
        'database': database,
        'kb': kb_meta if kb_meta is not None else kb_metadata(kb_root),
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


def _extraction_failure_findings(stderr: str, *, observed_at: str) -> list[Finding]:
    """Turn "Error during extraction" stderr lines into `error` findings.

    Confirmed against the real v2.5.1 binary (docs/evidence/osv-contract.md):
    a corrupt manifest logs one such line and is silently dropped from
    `results` -- everything else in the run still succeeds. Each line
    becomes its own finding so a broken manifest is never invisible just
    because another manifest in the same scan produced clean JSON.
    """
    findings: list[Finding] = []
    for line in _EXTRACTION_ERROR_LINE_RE.findall(stderr):
        bounded = line.strip()[:_MAX_ERROR_LINE_LEN]
        match = _MANIFEST_FILENAME_IN_LINE_RE.search(bounded)
        subject = match.group(1) if match else bounded
        findings.append(Finding(
            category='dependency',
            subject=subject,
            status='error',
            severity='unknown',
            confidence='high',
            evidence=(bounded,),
            action='osv-scanner could not parse this manifest; review it manually',
            observed_at=observed_at,
        ))
    return findings


def _find_fixed_version(vulnerability: dict[str, object], *, name: str, ecosystem: str,
                         skip_notes: list[str] | None = None, package_label: str = '') -> str | None:
    """Return the version to upgrade to, or None if no fix is recorded.

    Prefers an ECOSYSTEM-typed range's `fixed` event (a plain version
    string, e.g. "2.20.0") over a GIT-typed range's `fixed` event (a
    commit hash) when both are present, since the former is what a
    human upgrade instruction should name.
    """
    ecosystem_fixed: str | None = None
    other_fixed: str | None = None

    raw_affected = vulnerability.get('affected')
    if raw_affected is not None and not isinstance(raw_affected, list) and skip_notes is not None:
        skip_notes.append(f'{package_label}: vulnerability "affected" is not a list; ignored for fix lookup')

    for affected in _as_list(raw_affected):
        if not isinstance(affected, dict):
            continue
        package = _as_dict(affected.get('package'))
        if str(package.get('name')) != name or str(package.get('ecosystem')) != ecosystem:
            continue
        raw_ranges = affected.get('ranges')
        if raw_ranges is not None and not isinstance(raw_ranges, list) and skip_notes is not None:
            skip_notes.append(f'{package_label}: vulnerability "ranges" is not a list; ignored for fix lookup')
        for value_range in _as_list(raw_ranges):
            if not isinstance(value_range, dict):
                continue
            for event in _as_list(value_range.get('events')):
                if not (isinstance(event, dict) and 'fixed' in event):
                    continue
                fixed = _hashable_scalar(event['fixed'])
                if fixed is None:
                    continue
                if value_range.get('type') == 'ECOSYSTEM' and ecosystem_fixed is None:
                    ecosystem_fixed = fixed
                elif other_fixed is None:
                    other_fixed = fixed
    return ecosystem_fixed or other_fixed


def _vuln_reference_urls(vulnerability: dict[str, object], *, package_label: str, skip_notes: list[str]) -> list[str]:
    raw_refs = vulnerability.get('references')
    if raw_refs is not None and not isinstance(raw_refs, list):
        skip_notes.append(f'{package_label}: vulnerability "references" is not a list; ignored')
    return [
        str(reference['url']) for reference in _as_list(raw_refs)[:3]
        if isinstance(reference, dict) and reference.get('url')
    ]


def _package_findings(pkg_entry: dict[str, object], *, manifest_path: str | None,
                       kb_root: Path | None, observed_at: str,
                       packages_kb: dict[str, object], skip_notes: list[str],
                       unreadable_kb_reason: str | None) -> list[Finding]:
    package = _as_dict(pkg_entry.get('package'))
    name = str(package.get('name', ''))
    version = str(package.get('version', ''))
    ecosystem = str(package.get('ecosystem', ''))
    package_label = f'{name} {version} ({ecosystem})'
    subject = package_label
    manifest_label = manifest_path if manifest_path is not None else '(unknown manifest)'

    vulnerabilities = _as_list(pkg_entry.get('vulnerabilities'))
    if not vulnerabilities:
        return []

    kb_key = f'{ecosystem}:{name}:{version}'
    if unreadable_kb_reason is not None:
        # The --kb root itself is unreadable: never call read_kb, and
        # never let a per-package lookup silently claim "no page found"
        # for a root that was never actually readable (matches Task 3's
        # inventory_brew behavior).
        kb_context: dict[str, object] = {'status': 'unavailable', 'reason': unreadable_kb_reason}
    else:
        kb_context = _kb_context_for_osv(ecosystem, name, version, kb_root)
    packages_kb[kb_key] = kb_context
    kb_source_url = kb_context.get('source_url') if kb_context.get('status') == 'found' else None

    vulns_by_id: dict[str, dict[str, object]] = {}
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            skip_notes.append(f'{package_label}: a "vulnerabilities" entry is not an object; skipped')
            continue
        vuln_id = _hashable_scalar(vuln.get('id'))
        if vuln_id is None:
            skip_notes.append(f'{package_label}: a vulnerability "id" is not a scalar value; skipped from lookup')
            continue
        vulns_by_id[vuln_id] = vuln

    raw_groups = pkg_entry.get('groups')
    if raw_groups is not None and not isinstance(raw_groups, list):
        skip_notes.append(f'{package_label}: "groups" is not a list; ignored')
    groups = _as_list(raw_groups)

    findings: list[Finding] = []

    if not groups:
        # A package can have vulnerabilities without any (or any usable)
        # groups entry -- a detection must never vanish just because the
        # alias-grouping data is missing or malformed. Synthesize one
        # finding per (well-formed) vulnerability id instead.
        if vulns_by_id:
            skip_notes.append(
                f'{package_label}: vulnerabilities present but "groups" is missing, empty, or '
                f'malformed; synthesized one finding per vulnerability id instead'
            )
        for vuln_id, vuln in vulns_by_id.items():
            aliases = [
                alias for alias in (_hashable_scalar(a) for a in _as_list(vuln.get('aliases')))
                if alias is not None and alias != vuln_id
            ]
            fixed = _find_fixed_version(
                vuln, name=name, ecosystem=ecosystem, skip_notes=skip_notes, package_label=package_label,
            )
            action = f'upgrade to {fixed}' if fixed is not None else 'review advisory'
            reference_urls = _vuln_reference_urls(vuln, package_label=package_label, skip_notes=skip_notes)

            evidence: list[str] = [vuln_id] + aliases
            evidence.append(f'manifest: {manifest_label}')
            evidence.extend(reference_urls)
            if kb_source_url:
                evidence.append(kb_source_url)

            findings.append(Finding(
                category='dependency', subject=subject, status='detected',
                severity='unknown', confidence='high', evidence=tuple(evidence),
                action=action, observed_at=observed_at,
            ))
        return findings

    first_vuln = vulnerabilities[0] if isinstance(vulnerabilities[0], dict) else {}
    reference_urls = _vuln_reference_urls(first_vuln, package_label=package_label, skip_notes=skip_notes)

    for group in groups:
        if not isinstance(group, dict):
            skip_notes.append(f'{package_label}: a "groups" entry is not an object; skipped')
            continue

        raw_ids = group.get('ids')
        if raw_ids is not None and not isinstance(raw_ids, list):
            skip_notes.append(f'{package_label}: a group "ids" value is not a list; treated as empty')
        group_ids: list[str] = []
        for gid in _as_list(raw_ids):
            scalar = _hashable_scalar(gid)
            if scalar is None:
                skip_notes.append(f'{package_label}: a group id is not a scalar value; skipped')
                continue
            group_ids.append(scalar)

        raw_aliases = group.get('aliases')
        if raw_aliases is not None and not isinstance(raw_aliases, list):
            skip_notes.append(f'{package_label}: a group "aliases" value is not a list; treated as empty')
        alias_candidates: list[str] = []
        for alias in _as_list(raw_aliases):
            scalar = _hashable_scalar(alias)
            if scalar is None:
                skip_notes.append(f'{package_label}: a group alias is not a scalar value; skipped')
                continue
            alias_candidates.append(scalar)
        # "aliases (deduplicated)": drop aliases already present as a group
        # id so the same identifier is not repeated twice in evidence.
        group_aliases = [alias for alias in dict.fromkeys(alias_candidates) if alias not in group_ids]

        max_severity = group.get('max_severity')
        severity = str(max_severity) if max_severity else 'unknown'

        representative_vuln = None
        for group_id in group_ids:
            if group_id in vulns_by_id:
                representative_vuln = vulns_by_id[group_id]
                break

        action = 'review advisory'
        if representative_vuln is not None:
            fixed = _find_fixed_version(
                representative_vuln, name=name, ecosystem=ecosystem,
                skip_notes=skip_notes, package_label=package_label,
            )
            if fixed is not None:
                action = f'upgrade to {fixed}'

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


def _normalize_data(data: dict[str, object], *, kb_root: Path | None, observed_at: str) -> CheckResult:
    """Turn already-parsed `osv-scanner --format json` output into a CheckResult.

    Raises on any shape the defensive helpers above don't already cover;
    `_normalize_payload` (the only caller) wraps this in a catch-all so
    that ever happening is still `completion == 'error'`, never an
    uncaught exception.
    """
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

    kb_meta = kb_metadata(kb_root)
    unreadable_reason = kb_unreadable_reason(kb_meta)

    findings: list[Finding] = []
    manifest_paths: list[str] = []
    packages_kb: dict[str, object] = {}
    skip_notes: list[str] = []
    total_packages = 0
    packages_with_findings = 0

    for entry in results:
        if not isinstance(entry, dict):
            skip_notes.append('a "results" entry is not an object; skipped')
            continue
        source = entry.get('source')
        manifest_path = source.get('path') if isinstance(source, dict) else None
        if manifest_path:
            manifest_paths.append(str(manifest_path))

        raw_packages = entry.get('packages')
        if raw_packages is not None and not isinstance(raw_packages, list):
            skip_notes.append('a "packages" value is not a list; skipped')
        for pkg_entry in _as_list(raw_packages):
            if not isinstance(pkg_entry, dict):
                skip_notes.append('a "packages" entry is not an object; skipped')
                continue
            total_packages += 1
            vulnerabilities = _as_list(pkg_entry.get('vulnerabilities'))
            if vulnerabilities:
                packages_with_findings += 1
                findings.extend(_package_findings(
                    pkg_entry, manifest_path=manifest_path, kb_root=kb_root,
                    observed_at=observed_at, packages_kb=packages_kb,
                    skip_notes=skip_notes, unreadable_kb_reason=unreadable_reason,
                ))

    completion = 'complete'
    errors: tuple[str, ...] = ()
    if unreadable_reason is not None:
        completion = 'partial'
        errors = (unreadable_reason,)
    if skip_notes:
        completion = 'partial'
        errors = errors + tuple(skip_notes)

    metadata: dict[str, object] = {
        'packages': total_packages,
        'packages_with_findings': packages_with_findings,
        'manifests': len(results),
        'manifest_paths': manifest_paths,
        'packages_kb': packages_kb,
        'kb': kb_meta,
        'coverage': {'assessed': total_packages, 'unassessed': 0},
    }
    return CheckResult(name=_NAME, completion=completion, findings=tuple(findings), errors=errors, metadata=metadata)


def _normalize_payload(payload: str, *, kb_root: Path | None, observed_at: str) -> CheckResult:
    """Parse `osv-scanner ... --format json` output into a CheckResult.

    Pure function of the payload text: knows nothing about exit codes,
    the scanned project path, or invocation metadata (mode, database,
    command, engine version) -- `scan_project` layers those on. In
    particular this never emits the "no supported manifests" finding,
    because building its subject (the project path) requires information
    this function does not have.

    Two layers of defense against a hostile or malformed payload: known
    nested shapes are type-checked and skipped/coerced by `_normalize_data`
    and its helpers (recorded in `errors`, downgrading completion to
    'partial'); anything that still escapes those checks is caught here
    and reported as `completion == 'error'` with the exception text,
    rather than raising into the CLI.
    """
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        return CheckResult(
            name=_NAME, completion='error', findings=(),
            errors=(f'could not parse osv-scanner output: {exc}',),
            metadata=_base_metadata(kb_root=kb_root),
        )

    try:
        return _normalize_data(data, kb_root=kb_root, observed_at=observed_at)
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all, see docstring
        return CheckResult(
            name=_NAME, completion='error', findings=(),
            errors=(f'unexpected error parsing osv-scanner output: {exc!r}',),
            metadata=_base_metadata(kb_root=kb_root),
        )


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
        # Preserve the completion/errors the caller already decided (e.g.
        # 'partial' with a reason, if --kb was given but unreadable):
        # zero manifests found is not itself grounds to override that.
        name=result.name, completion=result.completion, findings=(finding,),
        errors=result.errors, metadata=metadata,
    )


def _handle_parseable_rc(*, stdout: str, stderr: str, path: Path, kb_root: Path | None, observed_at: str,
                          engine: dict[str, object], mode: str, database: str | None,
                          command: list[str]) -> CheckResult:
    """Handle an rc whose stdout is expected to be `--format json` output.

    Used for rc 0/1, and defensively for the (unobserved but spec'd) case
    of rc 127 carrying a non-empty `results`. Folds in per-manifest
    extraction failures from stderr (see docs/evidence/osv-contract.md):
    when present, findings from manifests that DID parse are kept, an
    `error`-status Finding is added per extraction-failure line, and the
    run is reported `partial` rather than `complete`.
    """
    parsed = _normalize_payload(stdout, kb_root=kb_root, observed_at=observed_at)
    metadata = _augment_metadata(parsed.metadata, engine=engine, mode=mode, database=database, command=command)
    if parsed.completion == 'error':
        return CheckResult(name=_NAME, completion='error', findings=(), errors=parsed.errors, metadata=metadata)

    completion = parsed.completion
    errors = parsed.errors
    findings = parsed.findings

    extraction_findings = _extraction_failure_findings(stderr, observed_at=observed_at)
    if extraction_findings:
        completion = 'partial'
        findings = findings + tuple(extraction_findings)
        bounded_tail = stderr.strip()[:_MAX_STDERR_TAIL_LEN]
        errors = errors + (f'osv-scanner reported manifest extraction failures: {bounded_tail}',)

    base_result = CheckResult(name=_NAME, completion=completion, findings=findings, errors=errors, metadata=metadata)
    if parsed.metadata.get('manifests') == 0:
        return _with_no_manifests_finding(base_result, path=path, observed_at=observed_at)
    return base_result


def scan_project(path: Path, *, online: bool, database: Path | None,
                  kb_root: Path | None = None, runner: Runner = run_command,
                  observed_at: str | None = None) -> CheckResult:
    """Check a project's dependency manifests for known vulnerabilities.

    Runs OSV-Scanner (`scan source --recursive --no-resolve --format
    json`) against `path`. Online lookups only happen when `online` is
    explicitly True; otherwise `database` must name a local offline
    database directory (passed via the engine's
    `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` env var -- see
    docs/evidence/osv-contract.md), or this returns `unavailable` without
    running the engine at all. In online mode `database` is always
    ignored (and reported as `None` in metadata) -- the engine never
    receives it, since `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` is only set
    for an offline run. `observed_at` defaults to the current UTC time
    when omitted; the CLI passes one run timestamp shared by every
    adapter it calls.
    """
    if observed_at is None:
        observed_at = _now_iso()
    path = Path(path).resolve()

    osv_path = shutil.which('osv-scanner')
    if osv_path is None:
        return _empty_result(
            completion='unavailable',
            errors=('osv-scanner not found on PATH',),
            kb_root=kb_root,
        )

    if online:
        database = None
    else:
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
        return _handle_parseable_rc(
            stdout=result.stdout, stderr=stderr, path=path, kb_root=kb_root, observed_at=observed_at,
            engine=engine_meta, mode=mode, database=database_str, command=argv,
        )

    if rc == 128:
        # ErrNoPackagesFound: no supported manifest was found at all.
        kb_meta = kb_metadata(kb_root)
        unreadable_reason = kb_unreadable_reason(kb_meta)
        base_completion = 'partial' if unreadable_reason is not None else 'complete'
        base_errors = (unreadable_reason,) if unreadable_reason is not None else ()
        metadata = _augment_metadata(
            _base_metadata(kb_root=kb_root, kb_meta=kb_meta),
            engine=engine_meta, mode=mode, database=database_str, command=argv,
        )
        base_result = CheckResult(name=_NAME, completion=base_completion, findings=(), errors=base_errors, metadata=metadata)
        return _with_no_manifests_finding(base_result, path=path, observed_at=observed_at)

    if rc == 127:
        # Empirically (docs/evidence/osv-contract.md), this binary only
        # exits 127 with an EMPTY `results`: a manifest with real findings
        # always forces rc=1 even when another manifest in the same run
        # failed to extract. This branch is a defensive fallback in case a
        # future release ever pairs rc=127 with a non-empty `results` --
        # if it does, treat it exactly like the rc 0/1 path above instead
        # of discarding the findings it produced.
        try:
            maybe_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            maybe_data = None
        if isinstance(maybe_data, dict) and maybe_data.get('results'):
            return _handle_parseable_rc(
                stdout=result.stdout, stderr=stderr, path=path, kb_root=kb_root, observed_at=observed_at,
                engine=engine_meta, mode=mode, database=database_str, command=argv,
            )

        metadata = _augment_metadata(
            _base_metadata(kb_root=kb_root), engine=engine_meta, mode=mode, database=database_str, command=argv,
        )
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

    metadata = _augment_metadata(
        _base_metadata(kb_root=kb_root), engine=engine_meta, mode=mode, database=database_str, command=argv,
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
