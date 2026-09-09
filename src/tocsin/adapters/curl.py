"""Reviewed Homebrew curl advisory matching.

This module owns three things for the curl formula: parsing an installed
release string into a comparable tuple (`parse_release`), loading and
strictly validating the curated advisory snapshot
(`load_records`/`DEFAULT_RECORDS`), and matching a `Package` against that
snapshot (`assess_curl`). Integration into the Homebrew inventory (calling
`assess_curl` only for `curl` packages, merging its findings and metadata)
lives in `tocsin.platforms.macos`, not here.

Why a curated snapshot rather than the full upstream feed: curl's own
machine-readable advisory feed (https://curl.se/docs/vuln.json, OSV schema)
holds roughly 215 records, but it does not structure applicability
prerequisites (TLS backend, protocol, build option) -- those live only in
each advisory's prose. Turning prose into a `requires` qualifier is a
manual, source-checked judgment call, so this snapshot ships only the six
records the OSS Security KB's curl page cites, each reviewed against the
upstream feed and (where relevant) the advisory's HTML page. See
docs/evidence/curl-advisories.md for the per-record review, including two
places where the KB page's stated fixed version disagrees with the feed
(the feed wins) and the one qualifier (CVE-2024-8096, GnuTLS-only) that
required reading advisory prose. Coverage is intentionally partial: a
`no-known-match` verdict here means "not one of these six reviewed
records", never "no curl vulnerabilities exist".

Snapshot record shape (see data/curl-advisories.json): `ranges` is the
canonical field for affected version spans -- a non-empty list of
`{"introduced": ..., "fixed": ...}` objects, all SEMVER-comparable via
`parse_release`. (Two of the six shipped records disagree with the KB page
on their `fixed` value; both use the upstream feed's value, noted in
`notes`.) There is no top-level `introduced`/`fixed` convenience field in
the *shipped* file -- `load_records` requires `ranges` -- but `assess_curl`
itself accepts either shape (`ranges`, or a flat `introduced`/`fixed` pair)
since it operates on arbitrary `list[dict]`, including small ad hoc
fixtures used by tests and any future caller that has not adopted `ranges`.

`requires` restricts applicability beyond the version range: currently the
only qualifier this module understands is `tls_backend` (Homebrew core
curl builds against openssl@3 per its formula, never GnuTLS/wolfSSL/
mbedTLS/Schannel/SecureTransport, so a `tls_backend` requirement other than
"openssl" can be resolved to no-known-match for a core-tap install, and
resolves to needs-review whenever the build's backend is unknown -- e.g. a
non-core tap). Any other `requires` key is unimplemented and always yields
needs-review, never detected, listing the unrecognized key so a reviewer
knows what was not evaluated.
"""

from __future__ import annotations

import importlib.resources
import json
from datetime import datetime, timezone
from pathlib import Path

from tocsin.models import CheckResult, Finding, Package

# The snapshot header fields (source, retrieval/review dates, reviewer)
# describe the curation process itself, not any one call's `records`
# argument -- `assess_curl`'s interface is `(package, records)` with no
# separate header parameter, so these constants are the single source of
# truth for metadata['snapshot']. They are kept in sync with
# data/curl-advisories.json by hand; test_shipped_snapshot_* below guards
# against the file and these constants drifting apart on the fields that
# matter (record content), and any change to the header fields must update
# both places.
SNAPSHOT_SOURCE = 'https://curl.se/docs/vuln.json'
SNAPSHOT_SOURCE_RETRIEVED = '2026-09-08'
SNAPSHOT_REVIEWED_AT = '2026-09-08'
SNAPSHOT_REVIEWER = 'Tocsin maintainers (LLM-assisted review of upstream advisories)'

_SCHEMA_VERSION = 1
_VALID_SEVERITIES = {'Low', 'Medium', 'High', 'Critical'}
_VALID_AFFECTS = {'tool', 'lib', 'both'}
_KNOWN_REQUIRES_KEYS = {'tls_backend'}

_CORE_TAP = 'homebrew/core'
_CORE_TLS_BACKEND = 'openssl'
_CORE_BACKEND_EVIDENCE = 'homebrew/core curl depends on openssl@3'

_TOP_LEVEL_KEYS = {
    'schema_version', 'package', 'source', 'source_retrieved', 'reviewed_at',
    'reviewer', 'records',
}
_RECORD_KEYS = {
    'id', 'aliases', 'summary', 'severity', 'ranges', 'affects', 'requires',
    'withdrawn', 'published', 'modified', 'sources', 'notes',
}

DEFAULT_RECORDS: Path = Path(str(importlib.resources.files('tocsin'))) / 'data' / 'curl-advisories.json'


def parse_release(value: str) -> tuple[int, int, int] | None:
    """Parse a plain `MAJOR.MINOR.PATCH` release string.

    Only the exact form `^[0-9]+\\.[0-9]+\\.[0-9]+$` (ASCII digits, no
    surrounding whitespace) is accepted, matched with `fullmatch` so a
    trailing newline cannot sneak past `$`'s "end of string or just before
    a trailing newline" behavior. Suffixes (`_1`), pre-release tags
    (`-rc1`, `-DEV`), and anything with fewer than three dot-separated
    components return `None` rather than being partially parsed --
    Homebrew revision suffixes are stripped by Task 3 before this ever
    runs, and prerelease/malformed strings are not upstream releases this
    module can safely compare against advisory ranges.
    """
    parts = value.split('.')
    if len(parts) != 3:
        return None
    if not all(part.isdigit() and part.isascii() for part in parts):
        return None
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def _record_ranges(record: dict) -> list[tuple[str, str]]:
    """Return a record's `(introduced, fixed)` pairs.

    `ranges` (a list of `{"introduced", "fixed"}` objects) is canonical;
    a flat top-level `introduced`/`fixed` pair is accepted as a shorthand
    for a single range, for small ad hoc records (tests, future callers)
    that have not adopted `ranges`. `load_records` only ever produces the
    canonical form for the shipped snapshot.
    """
    if 'ranges' in record:
        return [(r['introduced'], r['fixed']) for r in record['ranges']]
    return [(record['introduced'], record['fixed'])]


def _record_sources(record: dict) -> tuple[str, ...]:
    if 'sources' in record:
        return tuple(record['sources'])
    if 'source' in record:
        return (record['source'],)
    return ()


def _range_evidence(ranges: list[tuple[str, str]]) -> tuple[str, ...]:
    return tuple(f'range: >={introduced} <{fixed}' for introduced, fixed in ranges)


def _base_evidence(record: dict, ranges: list[tuple[str, str]]) -> tuple[str, ...]:
    record_id = str(record.get('id', '?'))
    aliases = tuple(str(a) for a in (record.get('aliases') or ()))
    return (record_id,) + aliases + _range_evidence(ranges) + _record_sources(record)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _snapshot_metadata() -> dict[str, object]:
    return {
        'source': SNAPSHOT_SOURCE,
        'source_retrieved': SNAPSHOT_SOURCE_RETRIEVED,
        'reviewed_at': SNAPSHOT_REVIEWED_AT,
        'reviewer': SNAPSHOT_REVIEWER,
    }


def _in_range(parsed: tuple[int, int, int], ranges: list[tuple[str, str]]) -> bool:
    for introduced, fixed in ranges:
        lo = parse_release(introduced)
        hi = parse_release(fixed)
        if lo is None or hi is None:
            continue  # unparseable range endpoint: never matches (load_records rejects this for shipped data)
        if lo <= parsed < hi:
            return True
    return False


def _fixed_for_matching_range(parsed: tuple[int, int, int], ranges: list[tuple[str, str]]) -> str:
    for introduced, fixed in ranges:
        lo = parse_release(introduced)
        hi = parse_release(fixed)
        if lo is not None and hi is not None and lo <= parsed < hi:
            return fixed
    return ranges[0][1]  # unreachable in practice; _in_range already confirmed a match


def _provenance_notes(package: Package) -> tuple[str, ...]:
    revision = package.provenance.get('revision')
    if revision is not None:
        return (f'homebrew revision _{revision}',)
    return ()


def assess_curl(
    package: Package,
    records: list[dict],
    *,
    observed_at: str | None = None,
) -> CheckResult:
    """Match an installed curl `Package` against reviewed advisory `records`.

    Matching order, per record: a `withdrawn` record can never yield
    `detected` (skipped, counted in metadata); an installed version that
    does not parse as a plain release yields exactly one `needs-review`
    finding for the whole package and stops (never `no-known-match`,
    never `error`); otherwise each record is range-checked
    (`introduced <= version < fixed`, inclusive/exclusive respectively)
    and, for records in range, `requires` is resolved against the
    package's Homebrew tap provenance before a status is assigned. See
    the module docstring for the `requires.tls_backend` resolution rules.

    A version that parses but matches no record's `detected` or
    `needs-review` outcome yields exactly one `no-known-match` finding
    naming how many reviewed records were compared and when the snapshot
    was last reviewed -- coverage is explicitly partial, never a clean
    bill of health for curl's full advisory history.
    """
    if observed_at is None:
        observed_at = _now_iso()
    subject = f'{package.name} {package.version}'
    records_total = len(records)

    metadata_base: dict[str, object] = {
        'records_total': records_total,
        'snapshot': _snapshot_metadata(),
        'coverage_note': (
            f'curated snapshot of {records_total} upstream advisories, not the full history'
        ),
    }

    parsed = parse_release(package.version)
    if parsed is None:
        finding = Finding(
            category='package',
            subject=subject,
            status='needs-review',
            severity='unknown',
            confidence='medium',
            evidence=(package.version, 'version is not a comparable upstream release'),
            action='confirm build backend/provenance before acting',
            observed_at=observed_at,
        )
        metadata = dict(metadata_base, records_compared=0, skipped_withdrawn=0, not_applicable=[])
        return CheckResult(
            name='curl', completion='complete', findings=(finding,), errors=(), metadata=metadata,
        )

    findings: list[Finding] = []
    not_applicable: list[dict[str, object]] = []
    skipped_withdrawn = 0
    records_compared = 0
    tap = package.provenance.get('tap')
    is_core_tap = tap == _CORE_TAP

    for record in records:
        if record.get('withdrawn') is not None:
            skipped_withdrawn += 1
            continue
        records_compared += 1

        ranges = _record_ranges(record)
        if not _in_range(parsed, ranges):
            continue

        requires = record.get('requires') or {}
        unhandled = set(requires) - _KNOWN_REQUIRES_KEYS
        record_id = str(record.get('id', '?'))
        base_evidence = _base_evidence(record, ranges)
        severity = str(record.get('severity', 'unknown'))
        fixed = _fixed_for_matching_range(parsed, ranges)

        if unhandled:
            evidence = base_evidence + tuple(
                f'unrecognized requires key: {key}' for key in sorted(unhandled)
            )
            findings.append(Finding(
                category='package', subject=subject, status='needs-review',
                severity=severity, confidence='medium', evidence=evidence,
                action='confirm build backend/provenance before acting',
                observed_at=observed_at,
            ))
            continue

        if not requires:
            if is_core_tap:
                evidence = base_evidence + _provenance_notes(package)
                findings.append(Finding(
                    category='package', subject=subject, status='detected',
                    severity=severity, confidence='high', evidence=evidence,
                    action=f'upgrade curl to {fixed} or later', observed_at=observed_at,
                ))
            else:
                reason = 'build provenance unknown: third-party or untapped formula may carry patches'
                evidence = base_evidence + (reason,)
                findings.append(Finding(
                    category='package', subject=subject, status='needs-review',
                    severity=severity, confidence='medium', evidence=evidence,
                    action='confirm build backend/provenance before acting',
                    observed_at=observed_at,
                ))
            continue

        # requires == {'tls_backend': ...} (the only known key).
        required_backend = requires['tls_backend']
        if is_core_tap:
            backend: str | None = _CORE_TLS_BACKEND
        else:
            backend = None

        if backend is None:
            reason = (
                f'build backend unknown: cannot confirm curl was built without '
                f'{required_backend} (tap={tap!r})'
            )
            evidence = base_evidence + (reason,)
            findings.append(Finding(
                category='package', subject=subject, status='needs-review',
                severity=severity, confidence='medium', evidence=evidence,
                action='confirm build backend/provenance before acting',
                observed_at=observed_at,
            ))
        elif backend != required_backend:
            reason = f'requires tls_backend={required_backend}; {_CORE_BACKEND_EVIDENCE}'
            not_applicable.append({'id': record_id, 'reason': reason})
        else:
            evidence = base_evidence + (_CORE_BACKEND_EVIDENCE,) + _provenance_notes(package)
            findings.append(Finding(
                category='package', subject=subject, status='detected',
                severity=severity, confidence='high', evidence=evidence,
                action=f'upgrade curl to {fixed} or later', observed_at=observed_at,
            ))

    if not findings:
        evidence = (
            f'compared against {records_compared} reviewed curl records '
            f'(curated snapshot reviewed {SNAPSHOT_REVIEWED_AT}, not the full curl advisory history)',
        )
        findings.append(Finding(
            category='package', subject=subject, status='no-known-match',
            severity='unknown', confidence='medium', evidence=evidence,
            action='no known match in the curated snapshot; keep curl updated',
            observed_at=observed_at,
        ))

    metadata = dict(
        metadata_base,
        records_compared=records_compared,
        skipped_withdrawn=skipped_withdrawn,
        not_applicable=not_applicable,
    )
    return CheckResult(
        name='curl', completion='complete', findings=tuple(findings), errors=(), metadata=metadata,
    )


def _fail(index: int | None, message: str) -> None:
    where = 'snapshot' if index is None else f'record[{index}]'
    raise ValueError(f'curl advisory snapshot: {where}: {message}')


def _validate_range(index: int, range_index: int, rng: object) -> None:
    if not isinstance(rng, dict):
        _fail(index, f'ranges[{range_index}] must be an object')
    missing = {'introduced', 'fixed'} - set(rng)
    if missing:
        _fail(index, f'ranges[{range_index}] missing key(s): {sorted(missing)}')
    for key in ('introduced', 'fixed'):
        value = rng[key]
        if not isinstance(value, str) or parse_release(value) is None:
            _fail(index, f'ranges[{range_index}].{key} is not a parseable release: {value!r}')


def _validate_record(index: int, record: object) -> None:
    if not isinstance(record, dict):
        _fail(index, 'must be an object')
    missing = _RECORD_KEYS - set(record)
    if missing:
        _fail(index, f'missing key(s): {sorted(missing)}')
    extra = set(record) - _RECORD_KEYS
    if extra:
        _fail(index, f'unexpected key(s): {sorted(extra)}')

    if not isinstance(record['id'], str) or not record['id']:
        _fail(index, 'id must be a non-empty string')
    if not isinstance(record['aliases'], list) or not all(isinstance(a, str) for a in record['aliases']):
        _fail(index, 'aliases must be a list of strings')
    if not isinstance(record['summary'], str) or not record['summary']:
        _fail(index, 'summary must be a non-empty string')
    if record['severity'] not in _VALID_SEVERITIES:
        _fail(index, f'severity must be one of {sorted(_VALID_SEVERITIES)}, got {record["severity"]!r}')
    if record['affects'] not in _VALID_AFFECTS:
        _fail(index, f'affects must be one of {sorted(_VALID_AFFECTS)}, got {record["affects"]!r}')
    if not isinstance(record['requires'], dict):
        _fail(index, 'requires must be an object')
    if record['withdrawn'] is not None and not isinstance(record['withdrawn'], str):
        _fail(index, 'withdrawn must be null or a string')
    for key in ('published', 'modified'):
        if not isinstance(record[key], str) or not record[key]:
            _fail(index, f'{key} must be a non-empty string')
    if not isinstance(record['sources'], list) or len(record['sources']) < 2:
        _fail(index, 'sources must be a list of at least two URLs')
    if not all(isinstance(u, str) and u.startswith('https://') for u in record['sources']):
        _fail(index, 'sources must all be https:// URLs')
    if not isinstance(record['notes'], str):
        _fail(index, 'notes must be a string')

    ranges = record['ranges']
    if not isinstance(ranges, list) or not ranges:
        _fail(index, 'ranges must be a non-empty list')
    for range_index, rng in enumerate(ranges):
        _validate_range(index, range_index, rng)


def load_records(path: Path = DEFAULT_RECORDS) -> list[dict]:
    """Load and strictly validate the curated curl advisory snapshot.

    Raises `ValueError` on any deviation from the schema documented in
    the module docstring: a missing or extra top-level key, the wrong
    `schema_version`, non-list `records`, a record missing a required
    key, an unrecognized `severity`, or a range endpoint that is not a
    plain parseable release. `json.JSONDecodeError` propagates directly
    for unparseable JSON. Callers (macos.py's Homebrew integration) treat
    any raised exception here as a corrupt-snapshot error: the curl
    package stays unassessed and the check completion becomes `partial`.
    """
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        _fail(None, f'must be an object, got {type(data).__name__}')

    missing = _TOP_LEVEL_KEYS - set(data)
    if missing:
        _fail(None, f'missing top-level key(s): {sorted(missing)}')
    extra = set(data) - _TOP_LEVEL_KEYS
    if extra:
        _fail(None, f'unexpected top-level key(s): {sorted(extra)}')

    if data['schema_version'] != _SCHEMA_VERSION:
        _fail(None, f'unsupported schema_version: {data["schema_version"]!r} (expected {_SCHEMA_VERSION})')
    if data['package'] != 'curl':
        _fail(None, f'package must be "curl", got {data["package"]!r}')
    for key in ('source', 'source_retrieved', 'reviewed_at', 'reviewer'):
        if not isinstance(data[key], str) or not data[key]:
            _fail(None, f'{key} must be a non-empty string')

    records = data['records']
    if not isinstance(records, list):
        _fail(None, f'records must be a list, got {type(records).__name__}')

    for index, record in enumerate(records):
        _validate_record(index, record)

    return records
