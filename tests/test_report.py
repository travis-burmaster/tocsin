import json

from tocsin.models import CheckResult, Finding
from tocsin.report import exit_code, render_json, render_text


def test_incomplete_check_wins_over_no_findings():
    result = CheckResult('clamav', 'unavailable', (), ('engine missing',), {})
    assert exit_code([result]) == 2


def test_error_finding_makes_complete_check_incomplete():
    finding = Finding('dependency', 'requirements.txt', 'error', 'unknown',
                      'high', ('parse failure',), 'review manifest', '2026-09-08T00:00:00Z')
    result = CheckResult('osv', 'complete', (finding,), (), {})
    assert exit_code([result]) == 2


def test_unassessed_coverage_gap_does_not_force_exit_2():
    finding = Finding('package', 'openssl@3 3.3.0', 'unassessed', 'unknown',
                      'high', (), 'no reviewed advisory adapter', '2026-09-08T00:00:00Z')
    result = CheckResult('brew', 'complete', (finding,), (), {'coverage': {'assessed': 1, 'unassessed': 1}})
    assert exit_code([result]) == 0


def test_mixed_findings_and_errors_preserved_in_json():
    detected = Finding('malware', '/tmp/evil.bin', 'detected', 'critical',
                        'high', ('signature: EICAR',), 'quarantine and investigate',
                        '2026-09-08T00:00:00Z')
    errored = Finding('dependency', 'requirements.txt', 'error', 'unknown',
                       'high', ('parse failure',), 'review manifest',
                       '2026-09-08T00:00:00Z')
    result = CheckResult('clamav', 'partial', (detected, errored),
                          ('scan of /private denied',), {'files_scanned': 3})

    payload = json.loads(render_json([result], {}))

    assert len(payload['results']) == 1
    serialized = payload['results'][0]
    assert serialized['completion'] == 'partial'
    assert serialized['errors'] == ['scan of /private denied']
    assert [f['status'] for f in serialized['findings']] == ['detected', 'error']
    assert serialized['findings'][0]['subject'] == '/tmp/evil.bin'
    assert serialized['findings'][1]['evidence'] == ['parse failure']
    assert serialized['metadata'] == {'files_scanned': 3}


def test_json_report_round_trip():
    finding = Finding('package', 'openssl@3 3.3.0', 'unassessed', 'unknown',
                       'high', (), 'no reviewed advisory adapter',
                       '2026-09-08T00:00:00Z')
    result = CheckResult('brew', 'complete', (finding,), (),
                          {'coverage': {'assessed': 1, 'unassessed': 1}})
    context = {
        'generated_at': None,
        'platform': 'Darwin',
        'architecture': 'arm64',
        'requested_scopes': ['brew'],
    }

    payload = json.loads(render_json([result], context))

    assert payload['schema_version'] == '1'
    assert payload['generated_at'] is None
    assert payload['host'] == {'platform': 'Darwin', 'architecture': 'arm64'}
    assert payload['requested_scopes'] == ['brew']
    assert payload['results'][0]['name'] == 'brew'
    assert payload['results'][0]['findings'][0]['subject'] == 'openssl@3 3.3.0'
    assert payload['results'][0]['metadata'] == {'coverage': {'assessed': 1, 'unassessed': 1}}


def test_control_characters_escaped_in_text_report():
    finding = Finding('malware', 'evil\x1b[31mname.bin', 'detected', 'critical',
                       'high', ('trigger:\x07bell',), 'quarantine\nand review',
                       '2026-09-08T00:00:00Z')
    result = CheckResult('clamav', 'complete', (finding,), ('boom\x00',), {})

    text = render_text([result], {'requested_scopes': ['files']})

    assert '\x1b' not in text
    assert '\x07' not in text
    assert '\x00' not in text
    assert '\\x1b[31mname.bin' in text
    assert '\\x07bell' in text
    assert '\\x00' in text
    assert '\\x0aand review' in text
