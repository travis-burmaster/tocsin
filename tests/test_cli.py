import json
import platform
import stat
from pathlib import Path

from tocsin.adapters import clamav as clamav_module
from tocsin.adapters import osv as osv_module
from tocsin.cli import main
from tocsin.models import CommandResult
from tocsin.platforms import macos

CLAMAV_FIXTURES = Path(__file__).parent / 'fixtures' / 'clamav'
CLAMAV_HELP_TEXT = (CLAMAV_FIXTURES / 'help.txt').read_text()
CLAMAV_VERSION_TEXT = (CLAMAV_FIXTURES / 'version.txt').read_text()


def test_empty_scope_rejected():
    assert main(['scan']) == 2


def test_output_file_created_with_mode_0600(tmp_path):
    output = tmp_path / "report.json"
    missing = tmp_path / "does-not-exist"

    # --files with a nonexistent path is a deterministic, adapter-free way
    # to get a fixed exit code here: cli.py reports "error" before ever
    # calling a runner, so this test exercises --output/--overwrite
    # mechanics only, independent of any particular scan scope.
    code = main(['scan', '--files', str(missing), '--format', 'json', '--output', str(output)])

    assert code == 2
    assert output.exists()
    mode = stat.S_IMODE(output.stat().st_mode)
    assert mode == 0o600


def test_existing_output_rejected_without_overwrite(tmp_path, capsys):
    output = tmp_path / "report.json"
    output.write_text("pre-existing content")
    missing = tmp_path / "does-not-exist"

    code = main(['scan', '--files', str(missing), '--format', 'json', '--output', str(output)])

    assert code == 2
    assert output.read_text() == "pre-existing content"
    captured = capsys.readouterr()
    assert "overwrite" in captured.err


def test_existing_output_replaced_with_overwrite(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("pre-existing content")
    missing = tmp_path / "does-not-exist"

    code = main(['scan', '--files', str(missing), '--format', 'json', '--output', str(output), '--overwrite'])

    assert code == 2
    assert "pre-existing content" not in output.read_text()
    mode = stat.S_IMODE(output.stat().st_mode)
    assert mode == 0o600


def test_doctor_reports_platform_python_and_capabilities(capsys):
    from tocsin.platforms import supported_capabilities

    code = main(['doctor'])

    assert code == 0
    out = capsys.readouterr().out
    assert f"platform: {platform.system()}" in out
    assert "python:" in out
    capabilities = supported_capabilities(platform.system())
    expected = ', '.join(sorted(capabilities)) if capabilities else 'none integrated yet'
    assert f"capabilities: {expected}" in out


def test_doctor_discovers_known_engines_without_installing(capsys):
    code = main(['doctor'])

    assert code == 0
    out = capsys.readouterr().out
    for name in ("brew", "clamscan", "osv-scanner"):
        assert f"{name}: " in out


def test_doctor_reports_clamscan_engine_and_flag_support(monkeypatch, capsys):
    monkeypatch.setattr(clamav_module.shutil, 'which', lambda name: '/opt/homebrew/bin/clamscan')

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        if argv[-1] == '--version':
            return CommandResult(0, CLAMAV_VERSION_TEXT, '', None)
        return CommandResult(0, CLAMAV_HELP_TEXT, '', None)

    code = main(['doctor'], runner=fake_runner)

    assert code == 0
    out = capsys.readouterr().out
    assert 'clamscan: engine 1.4.2, signatures 27540' in out
    assert 'required flags present' in out


def test_doctor_reports_kb_readability_and_commit(capsys):
    kb_root = Path(__file__).parent / 'fixtures' / 'kb'

    code = main(['doctor', '--kb', str(kb_root)])

    assert code == 0
    out = capsys.readouterr().out
    assert f"kb: {kb_root} (found)" in out
    assert "kb commit:" in out


def test_doctor_reports_missing_kb_path(tmp_path, capsys):
    missing = tmp_path / 'nowhere'

    code = main(['doctor', '--kb', str(missing)])

    assert code == 0
    out = capsys.readouterr().out
    assert f"kb: {missing} (not found)" in out


def test_scan_brew_with_kb_fixture_is_complete_and_unassessed(monkeypatch, capsys):
    # Never hit the real `brew` binary from a CLI-level test: patch the
    # macos adapter's shutil.which so it "finds" a fake brew, and inject a
    # fake runner all the way through main() so no subprocess ever runs.
    # 'curl' is deliberately not used here: since Task 5 it has its own
    # reviewed advisory adapter and is no longer generically unassessed
    # (see tests/test_curl.py and the curl-specific tests in test_cli.py).
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')
    kb_root = Path(__file__).parent / 'fixtures' / 'kb'
    payload = json.dumps({
        'formulae': [{
            'name': 'thing',
            'full_name': 'thing',
            'tap': 'homebrew/core',
            'installed': [{'version': '1.0.0'}],
        }],
        'casks': [],
    })

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, payload, '', None)

    code = main(['scan', '--brew', '--kb', str(kb_root)], runner=fake_runner)

    assert code == 0
    out = capsys.readouterr().out
    assert '== brew [complete] ==' in out
    assert 'coverage: assessed=0 unassessed=1' in out


def test_scan_project_with_fake_runner_online_is_complete(monkeypatch, capsys, tmp_path):
    # Never hit the real osv-scanner binary: patch the osv adapter's
    # shutil.which and inject a fake runner all the way through main().
    monkeypatch.setattr(osv_module.shutil, 'which', lambda name: '/opt/homebrew/bin/osv-scanner')
    version_output = 'osv-scanner version: 2.5.1\n'
    empty_json = json.dumps({'results': [], 'experimental_config': {}})

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        if argv[-1] == '--version':
            return CommandResult(0, version_output, '', None)
        return CommandResult(0, empty_json, '', None)

    code = main(['scan', '--project', str(tmp_path), '--online'], runner=fake_runner)

    assert code == 0  # complete, only an unassessed finding (not actionable)
    out = capsys.readouterr().out
    assert '== project [complete] ==' in out
    assert 'coverage: assessed=0 unassessed=1' in out


def test_scan_project_offline_without_database_is_unavailable(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(osv_module.shutil, 'which', lambda name: '/opt/homebrew/bin/osv-scanner')

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called when offline and no database is supplied')

    code = main(['scan', '--project', str(tmp_path)], runner=_forbidden)

    assert code == 2
    out = capsys.readouterr().out
    assert '== project [unavailable] ==' in out
    assert '--osv-database' in out


def test_scan_project_nonexistent_path_is_error_without_calling_adapter(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(osv_module.shutil, 'which', lambda name: '/opt/homebrew/bin/osv-scanner')
    missing = tmp_path / 'does-not-exist'

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called for a nonexistent --project path')

    code = main(['scan', '--project', str(missing), '--online'], runner=_forbidden)

    assert code == 2
    out = capsys.readouterr().out
    assert '== project [error] ==' in out
    assert str(missing) in out


def test_scan_project_path_that_is_a_file_is_error(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(osv_module.shutil, 'which', lambda name: '/opt/homebrew/bin/osv-scanner')
    a_file = tmp_path / 'not-a-directory.txt'
    a_file.write_text('oops')

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called for a --project path that is a file')

    code = main(['scan', '--project', str(a_file), '--online'], runner=_forbidden)

    assert code == 2
    out = capsys.readouterr().out
    assert '== project [error] ==' in out


def test_scan_files_nonexistent_path_is_error_without_calling_adapter(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(clamav_module.shutil, 'which', lambda name: '/opt/homebrew/bin/clamscan')
    missing = tmp_path / 'does-not-exist'

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called for a nonexistent --files path')

    code = main(['scan', '--files', str(missing)], runner=_forbidden)

    assert code == 2
    out = capsys.readouterr().out
    assert '== files [error] ==' in out
    assert str(missing) in out


def test_scan_files_with_fake_runner_is_complete(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(clamav_module.shutil, 'which', lambda name: '/opt/homebrew/bin/clamscan')
    (tmp_path / 'clean.txt').write_text('hello')

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        if argv[-1] == '--version':
            return CommandResult(0, CLAMAV_VERSION_TEXT, '', None)
        if argv[-1] == '--help':
            return CommandResult(0, CLAMAV_HELP_TEXT, '', None)
        return CommandResult(0, '----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 0\n', '', None)

    code = main(['scan', '--files', str(tmp_path)], runner=fake_runner)

    assert code == 0
    out = capsys.readouterr().out
    assert '== files [complete] ==' in out


def test_scan_reports_unsupported_scope_explicitly(monkeypatch, capsys):
    # Every scan scope now has an adapter on Darwin (Task 7 added the last
    # one, 'posture'), so simulate an unsupported platform instead: the CLI
    # must still report the scope as explicitly unsupported rather than
    # silently attempting or ignoring it.
    import tocsin.cli as cli_module

    monkeypatch.setattr(cli_module.platform, 'system', lambda: 'Linux')

    code = main(['scan', '--posture'])

    assert code == 2
    out = capsys.readouterr().out
    assert "posture" in out
    assert "not supported on this platform" in out
