"""Tests for the reviewed Homebrew curl advisory matcher (Task 5).

`assess_curl` matches an installed curl `Package` against a small,
human-reviewed snapshot of upstream curl advisories (`data/curl-advisories.json`,
loaded by `load_records`). See docs/evidence/curl-advisories.md for the
per-record source review and the KB-vs-feed discrepancy notes.
"""

from __future__ import annotations

import json

import pytest

from tocsin.adapters.curl import (
    DEFAULT_RECORDS,
    assess_curl,
    load_records,
    parse_release,
)
from tocsin.models import Package


# --- parse_release: semantic order and non-comparable versions -------------

def test_release_order():
    assert parse_release('8.10.0') > parse_release('8.9.0')


def test_non_release_versions_are_not_comparable():
    for raw in ('8.1.0-rc1', '8.1.0-DEV', '8.0.0_1', '8.1', ' 8.1.0', '8.1.0\n'):
        assert parse_release(raw) is None


def test_prerelease_is_needs_review_not_clean():
    package = Package('homebrew', 'curl', '8.1.0-rc1', {})
    record = {'id': 'TEST-ONLY', 'introduced': '7.0.0', 'fixed': '8.1.0', 'source': 'fixture'}
    result = assess_curl(package, [record])
    assert result.findings[0].status == 'needs-review'


def test_unknown_build_is_not_confirmed_vulnerable():
    package = Package('homebrew', 'curl', '8.0.0', {})
    record = {
        'id': 'TEST-ONLY', 'introduced': '7.0.0', 'fixed': '8.1.0',
        'requires': {'tls_backend': 'gnutls'}, 'source': 'fixture',
    }
    result = assess_curl(package, [record])
    assert result.findings[0].status == 'needs-review'


# --- assess_curl: boundaries -------------------------------------------------

_FIXTURE_RECORD = {
    'id': 'TEST-ONLY', 'aliases': ['CVE-TEST-0001'],
    'introduced': '7.69.0', 'fixed': '8.4.0', 'source': 'fixture',
    'severity': 'High',
}


def test_introduced_boundary_is_inclusive():
    package = Package('homebrew', 'curl', '7.69.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, [_FIXTURE_RECORD])
    assert result.findings[0].status == 'detected'


def test_fixed_boundary_is_exclusive():
    package = Package('homebrew', 'curl', '8.4.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, [_FIXTURE_RECORD])
    assert all(f.status != 'detected' for f in result.findings)
    assert result.findings[0].status == 'no-known-match'


def test_below_introduced_is_no_match():
    package = Package('homebrew', 'curl', '7.68.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, [_FIXTURE_RECORD])
    assert result.findings[0].status == 'no-known-match'


def test_multiple_ranges_are_all_checked():
    record = {
        'id': 'TEST-MULTI', 'aliases': [], 'severity': 'Medium', 'source': 'fixture',
        'ranges': [
            {'introduced': '7.0.0', 'fixed': '7.5.0'},
            {'introduced': '8.0.0', 'fixed': '8.2.0'},
        ],
    }
    package = Package('homebrew', 'curl', '8.1.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, [record])
    assert result.findings[0].status == 'detected'

    package_outside = Package('homebrew', 'curl', '7.8.0', {'tap': 'homebrew/core'})
    result_outside = assess_curl(package_outside, [record])
    assert result_outside.findings[0].status == 'no-known-match'


def test_withdrawn_record_never_detected_even_in_range():
    record = dict(_FIXTURE_RECORD, withdrawn='2024-01-01')
    package = Package('homebrew', 'curl', '8.0.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, [record])
    assert all(f.status != 'detected' for f in result.findings)
    assert result.metadata['skipped_withdrawn'] == 1
    assert result.findings[0].status == 'no-known-match'


# --- assess_curl: requires / provenance -------------------------------------

def test_core_tap_gnutls_requirement_is_no_match_not_a_finding():
    record = dict(_FIXTURE_RECORD, requires={'tls_backend': 'gnutls'})
    package = Package('homebrew', 'curl', '8.0.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, [record])
    assert all(f.status != 'detected' for f in result.findings)
    assert result.metadata['not_applicable']
    assert result.metadata['not_applicable'][0]['id'] == 'TEST-ONLY'


def test_core_tap_empty_requires_in_range_is_detected():
    package = Package('homebrew', 'curl', '8.0.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, [_FIXTURE_RECORD])
    finding = result.findings[0]
    assert finding.status == 'detected'
    assert finding.severity == 'High'
    assert finding.action == 'upgrade curl to 8.4.0 or later'


def test_non_core_tap_in_range_is_needs_review():
    package = Package('homebrew', 'curl', '8.0.0', {'tap': 'someone/tap'})
    result = assess_curl(package, [_FIXTURE_RECORD])
    assert result.findings[0].status == 'needs-review'


def test_core_tap_with_revision_is_detected_and_revision_noted():
    package = Package('homebrew', 'curl', '8.0.0', {'tap': 'homebrew/core', 'revision': '1'})
    result = assess_curl(package, [_FIXTURE_RECORD])
    finding = result.findings[0]
    assert finding.status == 'detected'
    assert any('revision' in item and '1' in item for item in finding.evidence)


def test_unhandled_requires_key_is_needs_review():
    record = dict(_FIXTURE_RECORD, requires={'protocol_feature': 'ldap'})
    package = Package('homebrew', 'curl', '8.0.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, [record])
    finding = result.findings[0]
    assert finding.status == 'needs-review'
    assert any('protocol_feature' in item for item in finding.evidence)


def test_no_match_when_version_parses_and_nothing_applies():
    package = Package('homebrew', 'curl', '9.0.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, [_FIXTURE_RECORD])
    finding = result.findings[0]
    assert finding.status == 'no-known-match'
    assert finding.severity == 'unknown'
    assert finding.confidence == 'medium'
    assert result.completion == 'complete'


def test_non_comparable_version_never_no_known_match_or_error():
    package = Package('homebrew', 'curl', '8.1.0-rc1', {'tap': 'homebrew/core'})
    result = assess_curl(package, [_FIXTURE_RECORD])
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.status == 'needs-review'
    assert finding.evidence[0] == '8.1.0-rc1'
    assert result.completion != 'error'


# --- load_records: strict schema validation ---------------------------------

def _valid_payload(**overrides):
    payload = {
        'schema_version': 1,
        'package': 'curl',
        'source': 'https://curl.se/docs/vuln.json',
        'source_retrieved': '2026-09-08',
        'reviewed_at': '2026-09-08',
        'reviewer': 'Tocsin maintainers (LLM-assisted review of upstream advisories)',
        'records': [
            {
                'id': 'CURL-CVE-2023-38545',
                'aliases': ['CVE-2023-38545'],
                'summary': 'SOCKS5 heap buffer overflow',
                'severity': 'High',
                'ranges': [{'introduced': '7.69.0', 'fixed': '8.4.0'}],
                'affects': 'both',
                'requires': {},
                'withdrawn': None,
                'published': '2023-10-11T08:00:00.00Z',
                'modified': '2026-05-19T11:21:50.00Z',
                'sources': [
                    'https://curl.se/docs/CVE-2023-38545.json',
                    'https://curl.se/docs/CVE-2023-38545.html',
                ],
                'notes': '',
            },
        ],
    }
    payload.update(overrides)
    return payload


def _write(tmp_path, payload):
    path = tmp_path / 'snapshot.json'
    path.write_text(json.dumps(payload))
    return path


def test_load_records_accepts_valid_snapshot(tmp_path):
    path = _write(tmp_path, _valid_payload())
    records = load_records(path)
    assert len(records) == 1
    assert records[0]['id'] == 'CURL-CVE-2023-38545'


def test_load_records_rejects_missing_top_level_key(tmp_path):
    payload = _valid_payload()
    del payload['reviewed_at']
    path = _write(tmp_path, payload)
    with pytest.raises(ValueError):
        load_records(path)


def test_load_records_rejects_wrong_schema_version(tmp_path):
    path = _write(tmp_path, _valid_payload(schema_version=2))
    with pytest.raises(ValueError):
        load_records(path)


def test_load_records_rejects_non_list_records(tmp_path):
    path = _write(tmp_path, _valid_payload(records={'not': 'a list'}))
    with pytest.raises(ValueError):
        load_records(path)


def test_load_records_rejects_bad_version_strings(tmp_path):
    payload = _valid_payload()
    payload['records'][0]['ranges'] = [{'introduced': '7.69.0-rc1', 'fixed': '8.4.0'}]
    path = _write(tmp_path, payload)
    with pytest.raises(ValueError):
        load_records(path)


def test_load_records_rejects_unknown_severity(tmp_path):
    payload = _valid_payload()
    payload['records'][0]['severity'] = 'Severe'
    path = _write(tmp_path, payload)
    with pytest.raises(ValueError):
        load_records(path)


def test_load_records_rejects_missing_record_key(tmp_path):
    payload = _valid_payload()
    del payload['records'][0]['sources']
    path = _write(tmp_path, payload)
    with pytest.raises(ValueError):
        load_records(path)


def test_load_records_accepts_multi_range_record(tmp_path):
    payload = _valid_payload()
    payload['records'][0]['ranges'] = [
        {'introduced': '7.0.0', 'fixed': '7.5.0'},
        {'introduced': '8.0.0', 'fixed': '8.2.0'},
    ]
    path = _write(tmp_path, payload)
    records = load_records(path)
    assert len(records[0]['ranges']) == 2


# --- the real shipped snapshot -----------------------------------------------

def test_shipped_snapshot_is_valid_and_fully_sourced():
    records = load_records(DEFAULT_RECORDS)
    assert len(records) == 6
    for record in records:
        assert len(record['sources']) >= 2
        assert all(url.startswith('https://') for url in record['sources'])
        assert record['published']
        assert record['modified']
        assert record['severity'] in {'Low', 'Medium', 'High', 'Critical'}
        for rng in record['ranges']:
            assert parse_release(rng['introduced']) is not None
            assert parse_release(rng['fixed']) is not None


def test_shipped_snapshot_matches_known_cve_boundary():
    records = load_records(DEFAULT_RECORDS)
    package = Package('homebrew', 'curl', '8.3.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, records)
    ids = {
        alias
        for finding in result.findings
        for alias in finding.evidence
        if str(alias).startswith('CVE-2023-38545')
    }
    assert ids
    assert any(f.status == 'detected' for f in result.findings)


@pytest.mark.parametrize(
    'cve, detected_version, clean_version',
    [
        # Both records document a DISAGREEMENT with the OSS Security KB
        # curl page (see docs/evidence/curl-advisories.md): the snapshot
        # follows the upstream feed's SEMVER range, so the boundary sits
        # one release later than the KB claims. These pins fail loudly if
        # a future snapshot edit silently adopts the KB's value.
        ('CVE-2024-7264', '8.9.0', '8.9.1'),   # KB says fixed=8.9.0; feed says 8.9.1
        ('CVE-2024-2004', '8.6.0', '8.7.0'),   # KB says fixed=8.7.1; feed says 8.7.0
    ],
)
def test_shipped_snapshot_pins_feed_favoured_boundaries(cve, detected_version, clean_version):
    records = load_records(DEFAULT_RECORDS)

    def cve_findings(version):
        package = Package('homebrew', 'curl', version, {'tap': 'homebrew/core'})
        result = assess_curl(package, records)
        return [f for f in result.findings if cve in f.evidence]

    (detected,) = cve_findings(detected_version)
    assert detected.status == 'detected'  # core tap: provenance is known
    assert not cve_findings(clean_version)


def test_shipped_snapshot_current_stable_is_no_known_match():
    records = load_records(DEFAULT_RECORDS)
    package = Package('homebrew', 'curl', '8.21.0', {'tap': 'homebrew/core'})
    result = assess_curl(package, records)
    assert len(result.findings) == 1
    assert result.findings[0].status == 'no-known-match'
