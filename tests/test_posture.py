import os
import plistlib
import sys

import pytest

from tocsin.models import CommandResult
from tocsin.platforms.macos_posture import parse_setting, scan_posture
from tocsin.report import exit_code

SETTING_NAMES = ('gatekeeper', 'sip', 'filevault', 'firewall', 'firewall_stealth')

_ARGV = {
    'gatekeeper': ['/usr/sbin/spctl', '--status'],
    'sip': ['/usr/bin/csrutil', 'status'],
    'filevault': ['/usr/bin/fdesetup', 'status'],
    'firewall': ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'],
    'firewall_stealth': ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getstealthmode'],
}

# Real captured outputs, from posture-research.md (macOS 26.6.2 build
# 25G83, arm64, captured 2026-09-08).
_ENABLED_OUTPUT = {
    'gatekeeper': 'assessments enabled',
    'sip': 'System Integrity Protection status: enabled.',
    'filevault': 'FileVault is On.',
    'firewall': 'Firewall is enabled. (State = 1)',
    'firewall_stealth': 'Firewall stealth mode is on',
}
_DISABLED_OUTPUT = {
    'gatekeeper': 'assessments disabled',
    'sip': 'System Integrity Protection status: disabled.',
    'filevault': 'FileVault is Off.',
    'firewall': 'Firewall is disabled. (State = 0)',
    'firewall_stealth': 'Firewall stealth mode is off',
}


# --- the brief's named test, verbatim ---------------------------------------

def test_unrecognized_setting_remains_unknown():
    assert parse_setting('sip', 0, 'unexpected future response') == 'unknown'


# --- parse_setting: table-driven over every recognized phrase ---------------

@pytest.mark.parametrize('name', SETTING_NAMES)
def test_parse_setting_recognizes_enabled_phrase(name):
    assert parse_setting(name, 0, _ENABLED_OUTPUT[name]) == 'enabled'


@pytest.mark.parametrize('name', SETTING_NAMES)
def test_parse_setting_recognizes_disabled_phrase(name):
    assert parse_setting(name, 0, _DISABLED_OUTPUT[name]) == 'disabled'


def test_parse_setting_firewall_state_2_is_enabled():
    assert parse_setting('firewall', 0, 'Firewall is enabled. (State = 2)') == 'enabled'


@pytest.mark.parametrize('name', SETTING_NAMES)
def test_parse_setting_nonzero_rc_with_matching_text_is_unknown(name):
    # Even output text that would otherwise match is never trusted when
    # the command itself did not exit 0.
    assert parse_setting(name, 1, _ENABLED_OUTPUT[name]) == 'unknown'


def test_parse_setting_trailing_whitespace_tolerated():
    assert parse_setting('gatekeeper', 0, '  assessments enabled  \n') == 'enabled'


def test_parse_setting_second_line_only_match_is_unknown():
    # Only the first non-empty line is judged; a matching phrase on a
    # later line (e.g. csrutil's "Configuration:" line) never counts.
    output = 'unexpected preamble\nSystem Integrity Protection status: enabled.'
    assert parse_setting('sip', 0, output) == 'unknown'


def test_parse_setting_firewall_enabled_without_state_suffix_is_unknown():
    # The exact recognized phrase includes "(State = 1)"/"(State = 2)";
    # a truncated or reworded line is never guessed from "enabled" alone.
    assert parse_setting('firewall', 0, 'Firewall is enabled.') == 'unknown'


def test_parse_setting_sip_custom_configuration_is_unknown():
    assert parse_setting('sip', 0, 'System Integrity Protection status: unknown (Custom Configuration).') == 'unknown'


def test_parse_setting_empty_output_is_unknown():
    assert parse_setting('filevault', 0, '') == 'unknown'


def test_parse_setting_unknown_setting_name_is_unknown():
    assert parse_setting('not-a-real-setting', 0, 'assessments enabled') == 'unknown'


def test_parse_setting_deferred_enablement_is_unknown():
    assert parse_setting('filevault', 0, 'FileVault is Off but will be enabled after the next restart (Deferred enablement).') == 'unknown'


def test_parse_setting_trailing_suffix_after_phrase_is_unknown():
    # A match must be the *entire* stripped line, not a substring: extra
    # trailing text (e.g. a deprecation notice) never counts.
    assert parse_setting('sip', 0, 'System Integrity Protection status: enabled. (deprecated)') == 'unknown'


def test_parse_setting_leading_prefix_before_phrase_is_unknown():
    assert parse_setting('gatekeeper', 0, 'Note: assessments enabled') == 'unknown'


# --- scan_posture: settings -------------------------------------------------

def _runner_from(outputs: dict[str, str]):
    """Fake runner returning rc=0 and the given per-setting stdout, keyed
    by setting name via argv matching."""
    argv_to_output = {tuple(_ARGV[name]): outputs[name] for name in outputs}

    def fake(argv, *, timeout, max_bytes, extra_env=None):
        key = tuple(argv)
        if key not in argv_to_output:
            raise AssertionError(f'unexpected argv: {argv}')
        return CommandResult(0, argv_to_output[key] + '\n', '', None)

    return fake


def _missing_runner(argv, *, timeout, max_bytes, extra_env=None):
    return CommandResult(None, '', '', 'missing')


def test_scan_posture_real_captured_outputs(tmp_path):
    # gatekeeper/sip/filevault enabled; firewall and stealth disabled --
    # exactly the mixed real-world snapshot from posture-research.md.
    outputs = dict(_ENABLED_OUTPUT)
    outputs['firewall'] = _DISABLED_OUTPUT['firewall']
    outputs['firewall_stealth'] = _DISABLED_OUTPUT['firewall_stealth']

    result = scan_posture(runner=_runner_from(outputs), launch_dirs=[])

    by_subject = {f.subject: f for f in result.findings}
    assert by_subject['gatekeeper'].status == 'no-known-match'
    assert by_subject['sip'].status == 'no-known-match'
    assert by_subject['filevault'].status == 'no-known-match'
    assert by_subject['firewall'].status == 'needs-review'
    assert by_subject['firewall_stealth'].status == 'needs-review'

    assert result.completion == 'complete'
    assert exit_code([result]) == 1
    assert result.metadata['coverage'] == {'assessed': 5, 'unassessed': 0}


def test_scan_posture_all_settings_enabled_is_clean(tmp_path):
    result = scan_posture(runner=_runner_from(_ENABLED_OUTPUT), launch_dirs=[])

    assert all(f.status == 'no-known-match' for f in result.findings if f.category == 'posture')
    assert result.completion == 'complete'
    assert exit_code([result]) == 0


def test_scan_posture_all_missing_is_unknown_complete_with_coverage_gap():
    result = scan_posture(runner=_missing_runner, launch_dirs=[])

    posture_findings = [f for f in result.findings if f.category == 'posture']
    assert len(posture_findings) == 5
    assert all(f.status == 'unassessed' for f in posture_findings)
    assert result.completion == 'complete'
    assert result.metadata['coverage'] == {'assessed': 0, 'unassessed': 5}
    assert exit_code([result]) == 0  # unassessed is a coverage gap, not actionable


def test_observed_at_is_shared_across_all_setting_findings():
    # scan_posture's observed_at is what the CLI threads through as its
    # one run timestamp (see tocsin.cli._run_scan); this exercises that
    # parameter directly rather than through main(), so launch_dirs can
    # be pinned to [] instead of reading the real host filesystem -- see
    # tests/test_integration.py's module docstring for why a CLI-level
    # (main()) --posture test is deliberately avoided there.
    fixed_at = '2026-01-01T00:00:00Z'

    result = scan_posture(runner=_missing_runner, launch_dirs=[], observed_at=fixed_at)

    assert result.findings, 'expected at least one finding from the five posture settings'
    assert {f.observed_at for f in result.findings} == {fixed_at}


def test_observed_at_defaults_to_current_time_when_omitted():
    result = scan_posture(runner=_missing_runner, launch_dirs=[])

    assert result.findings
    assert all(f.observed_at for f in result.findings)


def test_scan_posture_all_settings_permission_denied_is_error():
    def fake(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(None, '', '', 'permission')

    result = scan_posture(runner=fake, launch_dirs=[])

    assert result.completion == 'error'  # every command failed with permission
    assert all(f.status == 'unassessed' for f in result.findings if f.category == 'posture')


def test_scan_posture_single_permission_failure_is_partial():
    def fake(argv, *, timeout, max_bytes, extra_env=None):
        if argv == _ARGV['gatekeeper']:
            return CommandResult(None, '', '', 'permission')
        return CommandResult(0, 'assessments enabled\n', '', None)

    result = scan_posture(runner=fake, launch_dirs=[])

    assert result.completion == 'partial'


def test_scan_posture_timeout_is_partial():
    def fake(argv, *, timeout, max_bytes, extra_env=None):
        if argv == _ARGV['sip']:
            return CommandResult(None, '', '', 'timeout')
        return CommandResult(0, 'assessments enabled\n', '', None)

    result = scan_posture(runner=fake, launch_dirs=[])

    assert result.completion == 'partial'
    by_subject = {f.subject: f for f in result.findings}
    assert by_subject['sip'].status == 'unassessed'


def test_scan_posture_missing_executable_alone_stays_complete():
    # 'missing' (executable simply absent) never makes the check partial
    # on its own -- only other runner failures do.
    def fake(argv, *, timeout, max_bytes, extra_env=None):
        if argv == _ARGV['filevault']:
            return CommandResult(None, '', '', 'missing')
        return CommandResult(0, 'assessments enabled\n', '', None)

    result = scan_posture(runner=fake, launch_dirs=[])

    assert result.completion == 'complete'


def test_scan_posture_evidence_includes_command_rc_and_output():
    result = scan_posture(runner=_runner_from(_ENABLED_OUTPUT), launch_dirs=[])

    gatekeeper = next(f for f in result.findings if f.subject == 'gatekeeper')
    assert 'command: /usr/sbin/spctl --status' in gatekeeper.evidence
    assert 'rc: 0' in gatekeeper.evidence
    assert 'assessments enabled' in gatekeeper.evidence


def test_scan_posture_metadata_settings_and_host(tmp_path):
    result = scan_posture(runner=_runner_from(_ENABLED_OUTPUT), launch_dirs=[])

    assert set(result.metadata['settings']) == set(SETTING_NAMES)
    for name in SETTING_NAMES:
        entry = result.metadata['settings'][name]
        assert entry['state'] == 'enabled'
        assert entry['rc'] == 0
    assert result.metadata['host']['system'] == 'Darwin' or result.metadata['host']['system'] is not None
    assert len(result.metadata['commands']) == 5
    assert any('/System/Library' in s for s in result.metadata['limitations'])
    assert any('persistence' in s for s in result.metadata['limitations'])


# --- scan_posture: startup inventory ----------------------------------------

def _startup_findings(result):
    return [f for f in result.findings if f.category == 'startup']


def test_missing_launch_dir_has_status_missing_no_error(tmp_path):
    missing_dir = tmp_path / 'does-not-exist'

    result = scan_posture(runner=_missing_runner, launch_dirs=[missing_dir])

    assert result.metadata['launch_dirs'][str(missing_dir)]['status'] == 'missing'
    assert result.errors == ()
    assert result.completion == 'complete'


@pytest.mark.skipif(os.name != 'posix', reason='os.geteuid and chmod-based permission denial are POSIX-only')
def test_denied_launch_dir_is_error_string_and_partial(tmp_path):
    if os.geteuid() == 0:
        pytest.skip('root can read any directory regardless of mode')

    denied_dir = tmp_path / 'denied'
    denied_dir.mkdir()
    denied_dir.chmod(0)
    try:
        result = scan_posture(runner=_missing_runner, launch_dirs=[denied_dir])
    finally:
        denied_dir.chmod(0o700)

    assert result.metadata['launch_dirs'][str(denied_dir)]['status'] == 'denied'
    assert result.completion == 'partial'
    assert len(result.errors) == 1


@pytest.mark.skipif(os.name != 'posix', reason='os.geteuid and chmod-based permission denial are POSIX-only')
def test_launch_dir_with_unsearchable_parent_is_denied_and_partial(tmp_path):
    # Path.exists() itself can raise (EACCES/EPERM statting through an
    # unsearchable parent, e.g. a TCC-restricted path under ~/Library) --
    # this must degrade to partial, never crash the scan.
    if os.geteuid() == 0:
        pytest.skip('root can traverse any directory regardless of mode')

    parent = tmp_path / 'unsearchable'
    parent.mkdir()
    child = parent / 'LaunchAgents'
    parent.chmod(0)
    try:
        result = scan_posture(runner=_missing_runner, launch_dirs=[child])
    finally:
        parent.chmod(0o700)

    assert result.metadata['launch_dirs'][str(child)]['status'] == 'denied'
    assert result.completion == 'partial'
    assert len(result.errors) == 1


def test_launch_dir_path_that_is_a_file_is_unreadable_and_partial(tmp_path):
    # A launch-dir path that exists but is not a directory (e.g. a plain
    # file) must degrade to partial with a distinct status, not crash
    # with a NotADirectoryError.
    file_path = tmp_path / 'LaunchAgents'
    file_path.write_text('not a directory')

    result = scan_posture(runner=_missing_runner, launch_dirs=[file_path])

    assert result.metadata['launch_dirs'][str(file_path)]['status'] == 'unreadable'
    assert result.completion == 'partial'
    assert len(result.errors) == 1


def test_malformed_plist_is_skipped_and_partial(tmp_path):
    (tmp_path / 'com.example.bad.plist').write_bytes(b'this is not a plist, just garbage bytes\x00\x01\x02')

    result = scan_posture(runner=_missing_runner, launch_dirs=[tmp_path])

    startup = _startup_findings(result)
    assert len(startup) == 1
    assert startup[0].status == 'skipped'
    assert startup[0].action == 'plist could not be parsed; inspect manually'
    assert result.completion == 'partial'
    assert result.metadata['coverage']['unassessed'] >= 1


def test_oversized_plist_is_skipped(tmp_path):
    plist_path = tmp_path / 'com.example.huge.plist'
    with open(plist_path, 'wb') as handle:
        handle.write(b'\x00' * (1024 * 1024 + 1))

    result = scan_posture(runner=_missing_runner, launch_dirs=[tmp_path])

    startup = _startup_findings(result)
    assert len(startup) == 1
    assert startup[0].status == 'skipped'
    assert result.completion == 'partial'


def test_xml_plist_missing_absolute_executable_needs_review(tmp_path):
    plist_path = tmp_path / 'com.example.missing.plist'
    with open(plist_path, 'wb') as handle:
        plistlib.dump(
            {'Label': 'com.example.missing', 'ProgramArguments': ['/nonexistent/path/to/binary']},
            handle,
            fmt=plistlib.FMT_XML,
        )

    result = scan_posture(runner=_missing_runner, launch_dirs=[tmp_path])

    (finding,) = _startup_findings(result)
    assert finding.status == 'needs-review'
    assert finding.subject == 'com.example.missing: /nonexistent/path/to/binary'
    assert 'legitimate' in finding.action
    assert result.completion == 'complete'  # a needs-review signal is not a coverage gap


def test_binary_plist_program_in_tmp_needs_review_with_location_evidence(tmp_path):
    plist_path = tmp_path / 'com.example.tmp.plist'
    with open(plist_path, 'wb') as handle:
        plistlib.dump(
            {'Label': 'com.example.tmp', 'Program': '/tmp/some-suspicious-binary'},
            handle,
            fmt=plistlib.FMT_BINARY,
        )

    result = scan_posture(runner=_missing_runner, launch_dirs=[tmp_path])

    (finding,) = _startup_findings(result)
    assert finding.status == 'needs-review'
    assert any('/tmp/' in e for e in finding.evidence)


def test_binary_plist_program_in_resolved_var_tmp_needs_review(tmp_path):
    # macOS /var is itself a symlink to /private/var, so /private/var/tmp/
    # is a distinct unsafe-location prefix from /var/tmp/.
    plist_path = tmp_path / 'com.example.privatevartmp.plist'
    with open(plist_path, 'wb') as handle:
        plistlib.dump(
            {'Label': 'com.example.privatevartmp', 'Program': '/private/var/tmp/some-suspicious-binary'},
            handle,
            fmt=plistlib.FMT_BINARY,
        )

    result = scan_posture(runner=_missing_runner, launch_dirs=[tmp_path])

    (finding,) = _startup_findings(result)
    assert finding.status == 'needs-review'
    assert any('/private/var/tmp/' in e for e in finding.evidence)


def test_relative_program_needs_review(tmp_path):
    plist_path = tmp_path / 'com.example.relative.plist'
    with open(plist_path, 'wb') as handle:
        plistlib.dump({'Label': 'com.example.relative', 'Program': 'some-tool'}, handle)

    result = scan_posture(runner=_missing_runner, launch_dirs=[tmp_path])

    (finding,) = _startup_findings(result)
    assert finding.status == 'needs-review'
    assert 'PATH' in finding.action


def test_benign_plist_with_existing_executable_is_no_known_match(tmp_path):
    plist_path = tmp_path / 'com.example.benign.plist'
    with open(plist_path, 'wb') as handle:
        plistlib.dump({'Label': 'com.example.benign', 'Program': sys.executable}, handle)

    result = scan_posture(runner=_missing_runner, launch_dirs=[tmp_path])

    (finding,) = _startup_findings(result)
    assert finding.status == 'no-known-match'
    assert finding.status != 'needs-review'
    assert finding.confidence == 'medium'
    assert finding.action == 'none'
    # No claim about code signatures is ever made.
    for e in finding.evidence:
        assert 'signature' not in e.lower()


def test_disabled_true_recorded_in_evidence(tmp_path):
    plist_path = tmp_path / 'com.example.disabled.plist'
    with open(plist_path, 'wb') as handle:
        plistlib.dump({'Label': 'com.example.disabled', 'Program': sys.executable, 'Disabled': True}, handle)

    result = scan_posture(runner=_missing_runner, launch_dirs=[tmp_path])

    (finding,) = _startup_findings(result)
    assert 'Disabled: true' in finding.evidence


@pytest.mark.skipif(os.name != 'posix', reason='creating a symlink requires elevated privilege on Windows')
def test_symlinked_plist_skipped_and_counted(tmp_path):
    real_dir = tmp_path / 'real'
    real_dir.mkdir()
    target = real_dir / 'com.example.target.plist'
    with open(target, 'wb') as handle:
        plistlib.dump({'Label': 'com.example.target', 'Program': sys.executable}, handle)

    launch_dir = tmp_path / 'launch'
    launch_dir.mkdir()
    link = launch_dir / 'com.example.link.plist'
    link.symlink_to(target)

    result = scan_posture(runner=_missing_runner, launch_dirs=[launch_dir])

    assert _startup_findings(result) == []
    assert result.metadata['launch_dirs'][str(launch_dir)]['symlinks_skipped'] == 1
    assert result.metadata['launch_dirs'][str(launch_dir)]['plists'] == 0
    assert result.metadata['startup_items'] == 0


def test_non_plist_files_are_ignored(tmp_path):
    (tmp_path / 'README.txt').write_text('not a plist')

    result = scan_posture(runner=_missing_runner, launch_dirs=[tmp_path])

    assert _startup_findings(result) == []
    assert result.metadata['launch_dirs'][str(tmp_path)]['plists'] == 0


def test_startup_items_and_plist_counts_across_multiple_dirs(tmp_path):
    dir_a = tmp_path / 'a'
    dir_b = tmp_path / 'b'
    dir_a.mkdir()
    dir_b.mkdir()
    with open(dir_a / 'one.plist', 'wb') as handle:
        plistlib.dump({'Label': 'one', 'Program': sys.executable}, handle)
    with open(dir_b / 'two.plist', 'wb') as handle:
        plistlib.dump({'Label': 'two', 'Program': sys.executable}, handle)

    result = scan_posture(runner=_missing_runner, launch_dirs=[dir_a, dir_b])

    assert result.metadata['startup_items'] == 2
    assert len(_startup_findings(result)) == 2
    assert result.metadata['coverage']['assessed'] == 2  # both reviewed, no unknown settings assessed
