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


def test_stderr_cant_open_file_is_error_and_partial(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    (tmp_path / 'a.txt').write_text('x')

    def _scan(argv, *, timeout, max_bytes, extra_env=None):
        stdout = '----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 0\n'
        stderr = "/some/path: Can't open file or directory\n"
        return CommandResult(0, stdout, stderr, None)

    result = scan_files(tmp_path, runner=_runner(scan=_scan))

    assert result.completion == 'partial'
    assert any("Can't open file" in e for e in result.errors)


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


# --- temp file handling ---------------------------------------------------------

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
