import platform
import shutil
import stat
from pathlib import Path

import pytest

from tocsin.cli import main


def test_empty_scope_rejected():
    assert main(['scan']) == 2


def test_output_file_created_with_mode_0600(tmp_path):
    output = tmp_path / "report.json"

    code = main(['scan', '--posture', '--format', 'json', '--output', str(output)])

    assert code == 2  # posture adapter is not integrated yet
    assert output.exists()
    mode = stat.S_IMODE(output.stat().st_mode)
    assert mode == 0o600


def test_existing_output_rejected_without_overwrite(tmp_path, capsys):
    output = tmp_path / "report.json"
    output.write_text("pre-existing content")

    code = main(['scan', '--posture', '--format', 'json', '--output', str(output)])

    assert code == 2
    assert output.read_text() == "pre-existing content"
    captured = capsys.readouterr()
    assert "overwrite" in captured.err


def test_existing_output_replaced_with_overwrite(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("pre-existing content")

    code = main(['scan', '--posture', '--format', 'json', '--output', str(output), '--overwrite'])

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


def test_scan_brew_with_kb_fixture_is_complete_and_unassessed(capsys):
    if shutil.which('brew') is None:
        pytest.skip('brew not installed on this host')

    kb_root = Path(__file__).parent / 'fixtures' / 'kb'

    code = main(['scan', '--brew', '--kb', str(kb_root)])

    assert code == 0
    out = capsys.readouterr().out
    assert '== brew [complete] ==' in out
    assert 'coverage:' in out


def test_scan_reports_unsupported_scope_explicitly(capsys):
    # --posture has no adapter on any platform yet (Task 6 adds it), so this
    # stays a clean "unsupported"/"not integrated" signal regardless of host.
    code = main(['scan', '--posture'])

    assert code == 2
    out = capsys.readouterr().out
    assert "posture" in out
    assert "not supported on this platform" in out or "not integrated yet" in out
