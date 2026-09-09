"""End-to-end orchestration tests for `tocsin.cli.main` (Task 8).

These tests exercise the CLI's wiring across adapters rather than any one
adapter's internal logic: a single run timestamp shared by every adapter
call and the JSON report, cancellation handling for a KeyboardInterrupt
raised mid-scan, the `scan --help` privacy epilog, and an orchestration
run mixing a detected finding from one adapter with an unavailable
completion from another. Every runner here is a fake injected via
`main(..., runner=...)`; no real subprocess or engine is ever invoked, and
`--posture` (whose default launch directories are the real host
filesystem) is deliberately not used in this file -- see
tests/test_posture.py for launch-directory coverage with fixed dirs.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from tocsin.cli import main
from tocsin.models import CommandResult
from tocsin.platforms import macos, supported_capabilities

CLAMAV_FIXTURES = Path(__file__).parent / 'fixtures' / 'clamav'
CLAMAV_HELP_TEXT = (CLAMAV_FIXTURES / 'help.txt').read_text()
CLAMAV_VERSION_TEXT = (CLAMAV_FIXTURES / 'version.txt').read_text()


def _brew_payload(name: str, version: str, tap: str = 'homebrew/core') -> str:
    return json.dumps({
        'formulae': [{
            'name': name,
            'full_name': name,
            'tap': tap,
            'installed': [{'version': version}],
        }],
        'casks': [],
    })


def _patch_which(monkeypatch, paths: dict[str, str]) -> None:
    """Patch shutil.which for every adapter module at once.

    `macos`, `clamav`, and `osv` all `import shutil` -- it is the same
    module object in every one of them, so patching `macos.shutil.which`
    already changes what `clamav_module.shutil.which` and
    `osv_module.shutil.which` see too. A single dispatch function (keyed
    by executable name) avoids one adapter's patch silently clobbering
    another's within the same test.
    """
    def which(name: str) -> str | None:
        return paths.get(name)

    monkeypatch.setattr(macos.shutil, 'which', which)


# --- consistent run timestamp -----------------------------------------------

def test_run_timestamp_is_shared_across_adapters_and_report(monkeypatch, tmp_path):
    # --brew and --files use unrelated adapters (Homebrew inventory,
    # ClamAV file scan); every Finding they produce, plus the JSON
    # report's top-level generated_at, must carry the exact same
    # observed_at -- one run timestamp generated once by the CLI, not one
    # per adapter call.
    _patch_which(monkeypatch, {'brew': '/opt/homebrew/bin/brew', 'clamscan': '/opt/homebrew/bin/clamscan'})
    (tmp_path / 'clean.txt').write_text('hello')
    output = tmp_path / 'report.json'

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        if argv[0] == '/opt/homebrew/bin/brew':
            return CommandResult(0, _brew_payload('thing', '1.0.0'), '', None)
        if argv[-1] == '--version':
            return CommandResult(0, CLAMAV_VERSION_TEXT, '', None)
        if argv[-1] == '--help':
            return CommandResult(0, CLAMAV_HELP_TEXT, '', None)
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 0\n', '', None)

    code = main(
        ['scan', '--brew', '--files', str(tmp_path), '--format', 'json', '--output', str(output)],
        runner=fake_runner,
    )

    assert code == 0
    payload = json.loads(output.read_text())
    generated_at = payload['generated_at']
    assert generated_at is not None

    observed_timestamps = set()
    for result in payload['results']:
        for finding in result['findings']:
            observed_timestamps.add(finding['observed_at'])

    assert observed_timestamps, 'expected at least one finding to check timestamps against'
    assert observed_timestamps == {generated_at}


# --- cancellation ------------------------------------------------------------

def test_keyboard_interrupt_during_first_scope_is_recorded_and_exits_2(monkeypatch, tmp_path):
    _patch_which(monkeypatch, {'brew': '/opt/homebrew/bin/brew'})

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        interrupt = KeyboardInterrupt()
        interrupt.command_result = CommandResult(None, '', '', 'cancelled')
        raise interrupt

    code = main(['scan', '--brew', '--files', str(tmp_path), '--format', 'json'], runner=fake_runner)

    assert code == 2


def test_keyboard_interrupt_report_marks_interrupted_and_unstarted_scopes(monkeypatch, tmp_path, capsys):
    _patch_which(monkeypatch, {'brew': '/opt/homebrew/bin/brew'})

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        interrupt = KeyboardInterrupt()
        interrupt.command_result = CommandResult(None, '', '', 'cancelled')
        raise interrupt

    code = main(['scan', '--brew', '--files', str(tmp_path), '--format', 'json'], runner=fake_runner)

    assert code == 2
    out = capsys.readouterr().out
    payload = json.loads(out)

    by_name = {r['name']: r for r in payload['results']}
    assert set(by_name) == {'brew', 'files'}

    brew_result = by_name['brew']
    assert brew_result['completion'] == 'partial'
    assert brew_result['findings'] == []
    assert 'cancelled by user' in brew_result['errors']

    files_result = by_name['files']
    assert files_result['completion'] == 'unavailable'
    assert 'not run: scan cancelled' in files_result['errors']


def test_keyboard_interrupt_without_command_result_attribute_is_still_handled(monkeypatch, tmp_path, capsys):
    # The runner contract only guarantees command_result is attached when
    # a real subprocess was involved; the CLI must not assume it is
    # always present.
    _patch_which(monkeypatch, {'brew': '/opt/homebrew/bin/brew'})

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        raise KeyboardInterrupt()

    code = main(['scan', '--brew', '--format', 'json'], runner=fake_runner)

    assert code == 2
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload['results'][0]['name'] == 'brew'
    assert payload['results'][0]['completion'] == 'partial'
    assert 'cancelled by user' in payload['results'][0]['errors']


def test_keyboard_interrupt_still_renders_text_format(monkeypatch, tmp_path, capsys):
    _patch_which(monkeypatch, {'brew': '/opt/homebrew/bin/brew'})

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        raise KeyboardInterrupt()

    code = main(['scan', '--brew'], runner=fake_runner)

    assert code == 2
    out = capsys.readouterr().out
    assert '== brew [partial] ==' in out
    assert 'cancelled by user' in out


# --- privacy epilog -----------------------------------------------------------

def test_scan_help_epilog_states_privacy_behavior(capsys):
    code = main(['scan', '--help'])

    assert code == 0
    out = capsys.readouterr().out
    assert '--online' in out
    assert 'transmit' in out
    assert 'never' in out
    assert '0600' in out


# --- unsupported scope is never silently ignored ------------------------------

def test_unsupported_platform_scope_reports_explicit_error_and_exits_2(monkeypatch, capsys):
    import tocsin.cli as cli_module

    monkeypatch.setattr(cli_module.platform, 'system', lambda: 'Linux')

    code = main(['scan', '--posture', '--format', 'json'])

    assert code == 2
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert len(payload['results']) == 1
    result = payload['results'][0]
    assert result['name'] == 'posture'
    assert result['completion'] == 'unavailable'
    assert len(result['errors']) == 1
    assert result['errors'][0] == 'posture is not supported on this platform (Linux)'


def test_capabilities_are_darwin_only():
    assert supported_capabilities('Darwin') == frozenset({'brew', 'project', 'files', 'posture'})
    assert supported_capabilities('Linux') == frozenset()
    assert supported_capabilities('Windows') == frozenset()


# --- multi-adapter orchestration ----------------------------------------------

def test_orchestration_mixes_detected_and_unavailable_and_exits_2(monkeypatch, tmp_path):
    # --brew: a curl install matching one of the six reviewed advisory
    # records (CVE-2023-38545, fixed in 8.4.0) -> a real 'detected'
    # finding from tocsin.adapters.curl.assess_curl.
    # --project: offline with neither --online nor --osv-database is
    # unavailable without ever touching the runner (existing behavior).
    _patch_which(monkeypatch, {
        'brew': '/opt/homebrew/bin/brew',
        'osv-scanner': '/opt/homebrew/bin/osv-scanner',
    })

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        if argv[0] == '/opt/homebrew/bin/brew':
            return CommandResult(0, _brew_payload('curl', '8.0.0'), '', None)
        raise AssertionError(f'unexpected runner call: {argv}')

    output = tmp_path / 'report.json'
    code = main(
        [
            'scan', '--brew', '--project', str(tmp_path),
            '--format', 'json', '--output', str(output),
        ],
        runner=fake_runner,
    )

    assert code == 2
    if os.name == 'posix':
        # POSIX file-mode bits (0600) do not apply on Windows; the rest of
        # this test (JSON structure, both results present) still runs
        # there.
        mode = stat.S_IMODE(output.stat().st_mode)
        assert mode == 0o600

    payload = json.loads(output.read_text())
    by_name = {r['name']: r for r in payload['results']}
    assert set(by_name) == {'brew', 'project'}

    brew_result = by_name['brew']
    assert brew_result['completion'] == 'complete'
    detected = [f for f in brew_result['findings'] if f['status'] == 'detected']
    assert detected, f'expected a detected finding for curl 8.0.0, got: {brew_result["findings"]}'

    project_result = by_name['project']
    assert project_result['completion'] == 'unavailable'
    assert any('--osv-database' in e for e in project_result['errors'])
