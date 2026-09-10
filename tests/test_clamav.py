import os
import stat
from pathlib import Path

import pytest

from tocsin.adapters import clamav as clamav_module
from tocsin.adapters.clamav import ParsedScan, parse_clamscan_output, scan_files
from tocsin.models import CommandResult
from tocsin.report import exit_code

FIXTURES = Path(__file__).parent / 'fixtures' / 'clamav'
HELP_TEXT = (FIXTURES / 'help.txt').read_text()
HELP_MISSING_ALERT_EXCEEDS_MAX = (FIXTURES / 'help_missing_alert_exceeds_max.txt').read_text()
VERSION_TEXT = (FIXTURES / 'version.txt').read_text()
VERSION_GARBAGE = (FIXTURES / 'version_garbage.txt').read_text()

CLAMSCAN_PATH = '/opt/homebrew/bin/clamscan'


def _fake_which(monkeypatch, path=CLAMSCAN_PATH):
    monkeypatch.setattr(clamav_module.shutil, 'which', lambda name: path)


def _version_call(argv, *, timeout, max_bytes, extra_env=None):
    assert argv == [CLAMSCAN_PATH, '--version']
    return CommandResult(0, VERSION_TEXT, '', None)


def _help_call(argv, *, timeout, max_bytes, extra_env=None):
    assert argv == [CLAMSCAN_PATH, '--help']
    return CommandResult(0, HELP_TEXT, '', None)


def _runner(version=_version_call, help_=_help_call, scan=None):
    """Fake runner distinguishing --version, --help, and the scan call by argv."""

    def fake(argv, *, timeout, max_bytes, extra_env=None):
        if argv == [CLAMSCAN_PATH, '--version']:
            return version(argv, timeout=timeout, max_bytes=max_bytes, extra_env=extra_env)
        if argv == [CLAMSCAN_PATH, '--help']:
            return help_(argv, timeout=timeout, max_bytes=max_bytes, extra_env=extra_env)
        assert scan is not None, 'runner must not be called for the scan step in this test'
        return scan(argv, timeout=timeout, max_bytes=max_bytes, extra_env=extra_env)

    return fake


# --- named tests from the brief (write first, confirm RED) -----------------

def test_missing_engine_is_unavailable_with_no_command(monkeypatch, tmp_path):
    monkeypatch.setattr(clamav_module.shutil, 'which', lambda name: None)

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called when clamscan is missing')

    result = scan_files(tmp_path, runner=_forbidden)

    assert result.completion == 'unavailable'
    assert result.metadata.get('command') is None


def test_database_unavailable_rc2_no_matches_is_error_zero_findings(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('hello')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(2, '', 'database unavailable', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'error'
    assert result.findings == ()
    assert not any('no-known-match' in str(f.status) for f in result.findings)


def test_error_completion_never_looks_clean(monkeypatch, tmp_path):
    """An 'error' completion must never carry a no-known-match/clean finding."""
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('hello')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(2, '', 'database unavailable', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'error'
    assert all(f.status != 'no-known-match' for f in result.findings)
    assert exit_code([result]) == 2


@pytest.mark.skipif(os.name != 'posix', reason='creating a symlink requires elevated privilege on Windows')
def test_symlink_inside_root_not_followed(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    real_dir = tmp_path / 'real'
    real_dir.mkdir()
    target = real_dir / 'target.txt'
    target.write_text('hi')
    link = tmp_path / 'link.txt'
    link.symlink_to(target)

    captured_lists = []

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        list_arg = [a for a in argv if a.startswith('--file-list=')][0]
        list_path = list_arg.split('=', 1)[1]
        captured_lists.append(Path(list_path).read_text())
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\n', '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert str(link) not in captured_lists[0]
    assert result.metadata['symlinks_skipped'] == 1


def test_limits_exceeded_alert_is_skipped_and_partial(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    big = tmp_path / 'big.bin'
    big.write_text('x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = f'{big}: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 1\n'
        return CommandResult(1, stdout, '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    skipped = [f for f in result.findings if f.status == 'skipped']
    assert len(skipped) == 1
    assert skipped[0].subject == str(big)
    assert 'Heuristics.Limits.Exceeded.MaxFileSize' in skipped[0].evidence


# --- feature/version guard ---------------------------------------------------

def test_feature_guard_rejects_help_missing_alert_exceeds_max(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def _help(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, HELP_MISSING_ALERT_EXCEEDS_MAX, '', None)

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called for the scan when the feature guard fails')

    result = scan_files(tmp_path, runner=_runner(help_=_help, scan=_forbidden))

    assert result.completion == 'unavailable'
    assert any('--alert-exceeds-max' in e for e in result.errors)


def test_engine_metadata_parses_version_and_signature(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('hi')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\n', '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    engine = result.metadata['engine']
    assert engine['name'] == 'clamav'
    assert engine['version'] == '1.4.2'
    assert engine['signature_version'] == '27540'
    assert engine['signature_date'] == 'Tue Feb 11 09:22:11 2025'


def test_garbage_version_output_yields_none_fields(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('hi')

    def _version(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, VERSION_GARBAGE, '', None)

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\n', '', None)

    result = scan_files(tmp_path, runner=_runner(version=_version, scan=_scan))

    engine = result.metadata['engine']
    assert engine['version'] is None
    assert engine['signature_version'] is None
    assert engine['signature_date'] is None


# --- filename edge cases -----------------------------------------------------

def test_spaces_and_leading_dashes_are_scanned(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    weird = tmp_path / '-leading dash and spaces.txt'
    weird.write_text('hi')

    captured = {}

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        list_arg = [a for a in argv if a.startswith('--file-list=')][0]
        list_path = list_arg.split('=', 1)[1]
        captured['contents'] = Path(list_path).read_text()
        captured['argv'] = argv
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\n', '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert str(weird) in captured['contents']
    # No positional path arguments: every argv element after the binary is a flag.
    for arg in captured['argv'][1:]:
        assert arg.startswith('-')
    assert result.completion == 'complete'


@pytest.mark.skipif(os.name != 'posix', reason='Windows forbids control characters in filenames')
def test_newline_in_filename_is_skipped_and_partial(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    bad_name = 'bad\nname.txt'
    bad_path = tmp_path / bad_name
    bad_path.write_bytes(b'hi')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 0\n', '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    skipped = [f for f in result.findings if f.status == 'skipped']
    assert len(skipped) == 1
    assert '\\x0a' in skipped[0].subject
    assert result.metadata['ambiguous_skipped'] == 1


@pytest.mark.skipif(os.name != 'posix', reason="Windows forbids ':' in filenames")
def test_colon_space_in_filename_is_skipped(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    bad_path = tmp_path / 'weird: name.txt'
    bad_path.write_bytes(b'hi')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 0\n', '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    skipped = [f for f in result.findings if f.status == 'skipped']
    assert len(skipped) == 1
    assert result.metadata['ambiguous_skipped'] == 1


# --- unlistable directories ---------------------------------------------------

@pytest.mark.skipif(os.name != 'posix', reason='os.geteuid and chmod-based permission denial are POSIX-only')
def test_unreadable_subdirectory_is_skipped_and_partial(monkeypatch, tmp_path):
    """A directory os.walk cannot list must never be silently omitted.

    Without an `onerror` callback os.walk swallows the PermissionError and
    the scan reports 'complete' over a tree it only partly enumerated.
    """
    if os.geteuid() == 0:
        pytest.skip('root can read any directory regardless of mode')

    _fake_which(monkeypatch)
    readable = tmp_path / 'readable'
    readable.mkdir()
    (readable / 'a.txt').write_text('hello')
    denied = tmp_path / 'denied'
    denied.mkdir()
    (denied / 'hidden.txt').write_text('secret')
    denied.chmod(0)

    captured = {}

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        list_arg = [a for a in argv if a.startswith('--file-list=')][0]
        captured['contents'] = Path(list_arg.split('=', 1)[1]).read_text()
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\n', '', None)

    try:
        result = scan_files(tmp_path, runner=_runner(scan=_scan))
    finally:
        denied.chmod(0o700)

    assert result.completion == 'partial'
    skipped = [f for f in result.findings if f.status == 'skipped']
    assert len(skipped) == 1
    assert skipped[0].category == 'file'
    assert str(denied) in skipped[0].subject
    assert skipped[0].action == 'directory could not be listed; inspect manually'
    assert skipped[0].evidence and 'denied' in skipped[0].evidence[0]
    assert any('could not be listed' in e for e in result.errors)
    assert exit_code([result]) == 2
    # The readable half of the tree is still scanned.
    assert str(readable / 'a.txt') in captured['contents']
    assert 'hidden.txt' not in captured['contents']


# --- FOUND line classification (through scan_files) --------------------------

def test_encrypted_alert_is_skipped(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    archive = tmp_path / 'secret.zip'
    archive.write_text('zip')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = f'{archive}: Heuristics.Encrypted.Zip FOUND\n----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 1\n'
        return CommandResult(1, stdout, '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    assert len(result.findings) == 1
    assert result.findings[0].status == 'skipped'
    assert 'Heuristics.Encrypted.Zip' in result.findings[0].evidence


def test_eicar_signature_is_detected(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    eicar_path = tmp_path / 'eicar.txt'
    eicar_path.write_text('eicar-like')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = f'{eicar_path}: Eicar-Signature FOUND\n----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 1\n'
        return CommandResult(1, stdout, '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'complete'
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.status == 'detected'
    assert finding.confidence == 'high'
    assert 'Eicar-Signature' in finding.evidence
    assert exit_code([result]) == 1


def test_other_heuristic_is_needs_review(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    suspect = tmp_path / 'suspect.bin'
    suspect.write_text('x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = f'{suspect}: Heuristics.Broken.Executable FOUND\n----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 1\n'
        return CommandResult(1, stdout, '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'complete'
    finding = result.findings[0]
    assert finding.status == 'needs-review'
    assert finding.confidence == 'medium'


def test_found_line_naming_unrequested_path_is_ignored_and_recorded(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('hi')
    other = tmp_path / 'not-requested.txt'

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = f'{other}: Eicar-Signature FOUND\n----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 1\n'
        return CommandResult(1, stdout, '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    assert not any(f.subject == str(other) for f in result.findings)
    assert any(str(other) in e for e in result.errors)


# --- rc handling --------------------------------------------------------------

def test_rc1_with_detections_is_complete(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    target = tmp_path / 'virus.bin'
    target.write_text('x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = f'{target}: Eicar-Signature FOUND\n----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 1\n'
        return CommandResult(1, stdout, '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'complete'
    assert exit_code([result]) == 1


def test_rc0_clean_is_complete_zero_findings(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    (tmp_path / 'clean.txt').write_text('x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 0\n', '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'complete'
    assert result.findings == ()
    assert exit_code([result]) == 0
    assert result.metadata['summary']['scanned_files'] == '1'


def test_rc2_with_one_found_is_partial_keeping_finding(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    target = tmp_path / 'virus.bin'
    target.write_text('x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = f'{target}: Eicar-Signature FOUND\n----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 1\n'
        return CommandResult(2, stdout, 'some non-fatal warning', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    assert len(result.findings) == 1
    assert result.findings[0].status == 'detected'


@pytest.mark.skipif(os.name != 'posix', reason='Windows forbids control characters in filenames')
def test_rc2_no_found_retains_enumeration_skip_and_error(monkeypatch, tmp_path):
    """rc 2 with no parsed FOUND lines is still 'error' with zero PARSED
    alert findings (the brief's named case), but enumeration-time
    findings/errors (here: an ambiguous filename) are not discarded --
    "exit 2: partial or failed, retaining any findings" applies to those."""
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('hi')
    bad = tmp_path / 'bad\nname.txt'
    bad.write_bytes(b'x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(2, '', 'database unavailable', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'error'
    assert len(result.findings) == 1
    assert result.findings[0].status == 'skipped'
    assert any('database unavailable' in e for e in result.errors)
    assert any('ambiguous' in e for e in result.errors)


# --- non-UTF-8 filenames ---------------------------------------------------------

def test_ambiguity_reason_flags_non_utf8_filename():
    surrogate_path = '/tmp/x/bad\udcffname.txt'
    reason = clamav_module._ambiguity_reason(surrogate_path)
    assert reason is not None
    assert 'UTF-8' in reason


@pytest.mark.skipif(
    os.name != 'posix',
    reason='Windows filenames are UTF-16; os.fsencode semantics differ from POSIX',
)
def test_non_utf8_filename_on_disk_is_skipped_and_partial(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    bad_bytes = os.fsencode(str(tmp_path)) + b'/bad-\xff-name.txt'
    try:
        with open(bad_bytes, 'wb') as fh:
            fh.write(b'hi')
    except OSError:
        pytest.skip('filesystem rejects non-UTF-8 filenames')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 0\n', '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    skipped = [f for f in result.findings if f.status == 'skipped']
    assert len(skipped) == 1
    assert 'UTF-8' in ' '.join(skipped[0].evidence)


def test_argv_pins_safety_critical_flags_and_forbidden_absent(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('hi')
    captured = {}

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        captured['argv'] = list(argv)
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\n', '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    argv = captured['argv']
    required_flags = (
        '--stdout', '--infected', '--alert-exceeds-max=yes', '--alert-encrypted=yes',
        '--max-filesize=100M', '--max-scansize=500M', '--max-recursion=20',
        '--follow-dir-symlinks=0', '--follow-file-symlinks=0',
    )
    for flag in required_flags:
        assert flag in argv, f'missing required flag: {flag}'

    file_list_args = [a for a in argv if a.startswith('--file-list=')]
    assert len(file_list_args) == 1

    for arg in argv[1:]:
        assert arg.startswith('-'), f'unexpected positional argument in argv: {arg}'

    forbidden = ('--remove', '--move', '--copy', '--recursive', '--database')
    for arg in argv:
        for flag in forbidden:
            assert flag not in arg, f'forbidden flag {flag} found in argv element {arg}'

    command_meta = result.metadata['command']
    assert '<file-list>' in command_meta
    assert not any('tocsin-clamav-' in str(c) for c in command_meta)
    assert not any(str(tmp_path) in str(c) and c != '<file-list>' for c in command_meta)


# --- runner failures -----------------------------------------------------------

def test_timeout_keeps_complete_lines_drops_trailing_partial(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    good = tmp_path / 'good.bin'
    good.write_text('x')
    other = tmp_path / 'other.bin'
    other.write_text('y')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = f'{good}: Eicar-Signature FOUND\n{other}: Eicar-Sig'  # truncated mid-line
        return CommandResult(None, stdout, '', 'timeout')

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    assert len(result.findings) == 1
    assert result.findings[0].subject == str(good)
    assert any('timeout' in e for e in result.errors)


def test_output_limit_keeps_complete_lines_drops_trailing_partial(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    good = tmp_path / 'good.bin'
    good.write_text('x')
    other = tmp_path / 'other.bin'
    other.write_text('y')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = f'{good}: Eicar-Signature FOUND\n{other}: Eicar-Sig'
        return CommandResult(None, stdout, '', 'output-limit')

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    assert len(result.findings) == 1
    assert result.findings[0].subject == str(good)


def test_permission_failure_is_error(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(None, '', '', 'permission')

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'error'


def test_stdout_cant_open_file_is_error_and_partial(monkeypatch, tmp_path):
    # --stdout redirects clamscan's per-file diagnostics to stdout, not
    # stderr (the adapter's own --help fixture: "Write to stdout instead
    # of stderr"; clamav-research.md line 15). This is the realistic
    # production shape.
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = (
            "/some/path: Can't open file or directory\n"
            '----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 0\n'
        )
        return CommandResult(0, stdout, '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    assert any("Can't open file" in e for e in result.errors)


def test_stderr_cant_open_file_is_error_and_partial(monkeypatch, tmp_path):
    # Defensive coverage in case a build or wrapper still emits
    # diagnostics on stderr instead of (or as well as) stdout.
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = '----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 0\n'
        stderr = "/some/path: Can't open file or directory\n"
        return CommandResult(0, stdout, stderr, None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    assert any("Can't open file" in e for e in result.errors)


def test_parse_stdout_diagnostic_line_naming_requested_path_is_error():
    # Not one of the four known trigger substrings, but names a requested
    # path in the "<path>: <message>" shape clamscan's per-file
    # diagnostics take -- must still be captured as an error.
    #
    # The stdout line is built from str(requested[0]) rather than a
    # hardcoded '/tmp/thing.txt' literal: the adapter matches diagnostic
    # lines against `{str(p) for p in requested}` (clamav.py's
    # requested_set), and on Windows str(Path('/tmp/thing.txt')) renders
    # with backslashes ('\\tmp\\thing.txt'), which would never match a
    # forward-slash literal.
    requested = [Path('/tmp/thing.txt')]
    requested_str = str(requested[0])
    parsed = parse_clamscan_output(f'{requested_str}: Empty file\n', '', requested)
    assert any(requested_str in e for e in parsed.errors)
    assert parsed.detections == () and parsed.heuristics == () and parsed.skipped == ()


def test_parse_stdout_summary_lines_are_not_treated_as_errors():
    stdout = (
        '----------- SCAN SUMMARY -----------\n'
        'Known viruses: 123\n'
        'Scanned files: 1\n'
    )
    parsed = parse_clamscan_output(stdout, '', [])
    assert parsed.errors == ()


# --- summary parsing -----------------------------------------------------------

def test_summary_block_is_parsed():
    stdout = (
        '----------- SCAN SUMMARY -----------\n'
        'Known viruses: 8697472\n'
        'Engine version: 1.4.2\n'
        'Scanned directories: 1\n'
        'Scanned files: 3\n'
        'Infected files: 0\n'
        'Data scanned: 0.01 MB\n'
        'Data read: 0.00 MB (ratio 2.00:1)\n'
        'Time: 1.234 sec (0 m 1 s)\n'
    )
    parsed = parse_clamscan_output(stdout, '', [])

    assert parsed.summary['known_viruses'] == '8697472'
    assert parsed.summary['engine_version'] == '1.4.2'
    assert parsed.summary['scanned_files'] == '3'
    assert parsed.summary['infected_files'] == '0'
    assert parsed.summary['data_scanned'] == '0.01 MB'
    assert parsed.summary['data_read'] == '0.00 MB (ratio 2.00:1)'
    assert parsed.summary['time'] == '1.234 sec (0 m 1 s)'


def test_summary_absent_keys_are_none():
    parsed = parse_clamscan_output('no summary here\n', '', [])
    for key in ('known_viruses', 'engine_version', 'scanned_files', 'infected_files', 'data_scanned', 'data_read', 'time'):
        assert parsed.summary[key] is None


def test_summary_parses_total_errors_and_scanned_directories():
    stdout = (
        '----------- SCAN SUMMARY -----------\n'
        'Scanned directories: 0\n'
        'Scanned files: 0\n'
        'Total errors: 2\n'
    )
    parsed = parse_clamscan_output(stdout, '', [])

    assert parsed.summary['total_errors'] == '2'
    assert parsed.summary['scanned_directories'] == '0'


# --- unnamed file errors (ClamAV 1.5.4 live-engine behaviour: a
# permission-denied file under --infected produces NO per-file line on
# either stream, only rc 2 / "Total errors: N" / a Scanned-files gap) ------

def test_rc2_unnamed_file_error_is_informative_not_no_stderr(monkeypatch, tmp_path):
    """rc 2, no FOUND lines, 'Total errors: 1' and 'Scanned files: 0' for
    two requested files: real 1.5.4 output for one unreadable file among
    two (see live-engine-evidence.md). Must name the error count and the
    scanned/requested gap instead of '(no stderr)', with zero findings."""
    _fake_which(monkeypatch)
    (tmp_path / 'clean.txt').write_text('hi')
    (tmp_path / 'noperm.txt').write_text('hi')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = (
            '----------- SCAN SUMMARY -----------\n'
            'Known viruses: 3628058\n'
            'Engine version: 1.5.4\n'
            'Scanned directories: 1\n'
            'Scanned files: 0\n'
            'Infected files: 0\n'
            'Total errors: 1\n'
            'Data scanned: 0.00 MB\n'
            'Time: 0.010 sec (0 m 0 s)\n'
        )
        return CommandResult(2, stdout, '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'error'
    assert result.findings == ()
    assert any('1 file error' in e for e in result.errors)
    assert any('0 of 2' in e for e in result.errors)
    assert not any('(no stderr)' in e for e in result.errors)


def test_rc1_found_line_with_unnamed_error_is_partial_with_coverage_gap(monkeypatch, tmp_path):
    """rc 1 with one FOUND line plus 'Total errors: 1' and a scanned-files
    gap (one of two requested files was not scanned): the detection is
    kept, completion is forced to partial, and coverage reflects the
    actual scanned count, not the requested count."""
    _fake_which(monkeypatch)
    eicar = tmp_path / 'eicar.txt'
    eicar.write_text('eicar-like')
    (tmp_path / 'noperm.txt').write_text('hi')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = (
            f'{eicar}: Eicar-Signature FOUND\n'
            '----------- SCAN SUMMARY -----------\n'
            'Scanned files: 1\n'
            'Infected files: 1\n'
            'Total errors: 1\n'
        )
        return CommandResult(1, stdout, '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    detected = [f for f in result.findings if f.status == 'detected']
    assert len(detected) == 1
    assert detected[0].subject == str(eicar)
    assert result.metadata['coverage'] == {'assessed': 1, 'unassessed': 1}
    assert exit_code([result]) == 2


def test_rc0_clean_with_zero_total_errors_and_full_scan_is_complete(monkeypatch, tmp_path):
    """rc 0, 'Total errors: 0', Scanned files == requested: a clean run
    must remain complete with zero findings even with the new summary
    keys present."""
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('hi')
    (tmp_path / 'b.txt').write_text('hi')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = (
            '----------- SCAN SUMMARY -----------\n'
            'Scanned files: 2\n'
            'Infected files: 0\n'
            'Total errors: 0\n'
        )
        return CommandResult(0, stdout, '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'complete'
    assert result.findings == ()
    assert exit_code([result]) == 0
    assert result.metadata['coverage']['assessed'] == 2


# --- temp file handling ---------------------------------------------------------

@pytest.mark.skipif(os.name != 'posix', reason='POSIX file-mode bits (0600) do not apply on Windows')
def test_temp_file_mode_0600_and_deleted_after(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('hi')
    captured = {}

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        list_arg = [a for a in argv if a.startswith('--file-list=')][0]
        list_path = list_arg.split('=', 1)[1]
        captured['path'] = list_path
        mode = stat.S_IMODE(os.stat(list_path).st_mode)
        assert mode == 0o600
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\n', '', None)

    scan_files(tmp_path, runner=_runner(scan=_scan))

    assert not os.path.exists(captured['path'])


# --- enumeration cap -------------------------------------------------------------

def test_enumeration_cap_is_enforced(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    monkeypatch.setattr(clamav_module, '_MAX_FILES', 3)
    for i in range(5):
        (tmp_path / f'f{i}.txt').write_text('x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 3\n', '', None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    assert any('3' in e for e in result.errors)


# --- single file root -------------------------------------------------------------

def test_regular_file_root_scans_just_that_file(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    target = tmp_path / 'single.txt'
    target.write_text('hi')

    captured = {}

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        list_arg = [a for a in argv if a.startswith('--file-list=')][0]
        list_path = list_arg.split('=', 1)[1]
        captured['contents'] = Path(list_path).read_text()
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\n', '', None)

    result = scan_files(target, runner=_runner(scan=_scan))

    assert captured['contents'].strip() == str(target)
    assert result.completion == 'complete'


# --- parse_clamscan_output direct unit tests -------------------------------------

def test_parse_unrequested_path_recorded_as_error():
    parsed = parse_clamscan_output('/not/requested: Eicar-Signature FOUND\n', '', [Path('/requested.txt')])
    assert parsed.detections == ()
    assert any('/not/requested' in e for e in parsed.errors)


def test_parse_bounds_stderr_error_lines():
    lines = "\n".join(f"/tmp/f{i}: Can't open file" for i in range(60))
    parsed = parse_clamscan_output('', lines, [])
    assert len(parsed.errors) <= 50


# --- optional local integration: a real clamscan binary with a working
# signature database. Not run on the development host -- clamscan is not
# installed there and must not be installed just for this task (see
# docs/evidence/clamav-contract.md). Set TOCSIN_CLAMSCAN to a clamscan
# binary path with a working database to exercise this.

_REAL_CLAMSCAN = os.environ.get('TOCSIN_CLAMSCAN')

# Harmless test string recognized by every ClamAV signature database.
# Written only inside tmp_path and never distributed.
_EICAR = (
    r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
)


@pytest.mark.skipif(
    not _REAL_CLAMSCAN,
    reason='set TOCSIN_CLAMSCAN to a clamscan binary with a working database to run the real EICAR integration test',
)
def test_real_clamscan_detects_eicar(monkeypatch, tmp_path):
    monkeypatch.setattr(clamav_module.shutil, 'which', lambda name: _REAL_CLAMSCAN)
    eicar_path = tmp_path / 'eicar.com'
    eicar_path.write_text(_EICAR)

    from tocsin.runner import run_command

    result = scan_files(tmp_path, runner=run_command)

    assert result.completion == 'complete'
    assert any(f.status == 'detected' for f in result.findings)


@pytest.mark.skipif(
    not _REAL_CLAMSCAN,
    reason='set TOCSIN_CLAMSCAN to a clamscan binary with a working database to run the real permission-denied integration test',
)
@pytest.mark.skipif(os.name != 'posix', reason='chmod-based permission denial is POSIX-only')
def test_real_clamscan_unreadable_file_is_informative_error(tmp_path):
    """Live-engine confirmation of the ClamAV 1.5.4 behaviour recorded in
    live-engine-evidence.md: --file-list has clean.txt and a chmod-000
    file; clamscan itself is left on PATH (shutil.which untouched), so
    this exercises the real engine-discovery probe too. rc must be 2, the
    unnamed file error must be reported informatively (never
    '(no stderr)'), and no finding is ever invented."""
    if os.geteuid() == 0:
        pytest.skip('root can read any file regardless of mode')

    clean = tmp_path / 'clean.txt'
    clean.write_text('hello')
    noperm = tmp_path / 'noperm.txt'
    noperm.write_text('hello')
    noperm.chmod(0)

    from tocsin.runner import run_command

    try:
        result = scan_files(tmp_path, runner=run_command)
    finally:
        noperm.chmod(0o600)

    assert result.completion == 'error'
    assert result.findings == ()
    assert result.metadata['command'] is not None  # sanity: a real scan ran, not a probe failure
    assert any('1 file error' in e for e in result.errors)
    assert any('1 of 2' in e for e in result.errors)
    assert not any('(no stderr)' in e for e in result.errors)
    assert exit_code([result]) == 2


@pytest.mark.skipif(
    not _REAL_CLAMSCAN,
    reason='set TOCSIN_CLAMSCAN to a clamscan binary with a working database to run the real oversized-file limit check',
)
def test_real_clamscan_undersized_random_file_not_flagged(tmp_path):
    """Live-engine sanity check: a 300 KB random file is well under the
    production 100M --max-filesize limit and must scan clean. ClamAV
    1.5.4 omits the 'Total errors' line entirely on a clean run (confirmed
    by direct probe against this engine -- it does not print
    'Total errors: 0'), so the new total_errors summary key must parse as
    None here rather than triggering the unnamed-file-error path."""
    import random

    target = tmp_path / 'random.bin'
    target.write_bytes(bytes(random.getrandbits(8) for _ in range(300 * 1024)))

    from tocsin.runner import run_command

    result = scan_files(tmp_path, runner=run_command)

    assert result.completion == 'complete'
    assert result.findings == ()
    assert result.metadata['summary']['total_errors'] is None
    assert result.metadata['summary']['scanned_files'] == '1'
