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
