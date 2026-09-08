import platform
import stat

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
    code = main(['doctor'])

    assert code == 0
    out = capsys.readouterr().out
    assert f"platform: {platform.system()}" in out
    assert "python:" in out
    # No adapter is integrated yet in this task, on any platform.
    assert "capabilities: none integrated yet" in out


def test_doctor_discovers_known_engines_without_installing(capsys):
    code = main(['doctor'])

    assert code == 0
    out = capsys.readouterr().out
    for name in ("brew", "clamscan", "osv-scanner"):
        assert f"{name}: " in out


def test_scan_reports_unsupported_scope_explicitly(capsys):
    code = main(['scan', '--brew'])

    assert code == 2
    out = capsys.readouterr().out
    assert "brew is not supported on this platform" in out
