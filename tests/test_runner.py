import json
import os
import signal
import subprocess
import sys
import time

import pytest

from tocsin import runner
from tocsin.models import CommandResult
from tocsin.runner import run_command

# Every test that actually starts a child process needs POSIX process
# groups. Registered once here so those tests are skipped on Windows --
# this is one of two mechanisms that keep the CI matrix
# (.github/workflows/tests.yml) green off macOS, not the whole story by
# itself: CLI-level tests in tests/test_cli.py and tests/test_integration.py
# stay portable a different way (the `force_darwin` fixture in
# tests/conftest.py), since they need Darwin's capability set to reach
# an adapter at all, regardless of the host OS actually running pytest.
# The Windows branch gets its own test below that patches os.name
# instead of the platform.
posix_only = pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")


@posix_only
def test_missing_command_is_explicit():
    result = run_command(['/nonexistent/tocsin-tool'], timeout=1, max_bytes=1024)
    assert result.failure == 'missing'


@posix_only
def test_child_environment_is_minimal(monkeypatch):
    monkeypatch.setenv('HOMEBREW_LEAKED', '1')
    monkeypatch.setenv('DYLD_INSERT_LIBRARIES', '/tmp/x.dylib')
    result = run_command([sys.executable, '-c',
                         'import os, json; print(json.dumps(dict(os.environ)))'],
                         timeout=5, max_bytes=65536, extra_env={'TOCSIN_TEST': 'y'})
    env = json.loads(result.stdout)
    assert 'HOMEBREW_LEAKED' not in env and 'DYLD_INSERT_LIBRARIES' not in env
    assert env['TOCSIN_TEST'] == 'y'
    assert 'PATH' in env and 'HOME' in env


@posix_only
def test_timeout_kills_sleeping_child():
    start = time.monotonic()
    result = run_command(
        [sys.executable, '-c', 'import time; time.sleep(5)'],
        timeout=1,
        max_bytes=1024,
    )
    elapsed = time.monotonic() - start

    assert result.failure == 'timeout'
    assert result.returncode is None
    assert elapsed < 3  # killed well before the child's 5s sleep would finish


@posix_only
def test_output_limit_returns_captured_prefix():
    flooder = (
        "import sys\n"
        "while True:\n"
        "    sys.stdout.write('A' * 4096)\n"
        "    sys.stdout.flush()\n"
        "    sys.stderr.write('B' * 4096)\n"
        "    sys.stderr.flush()\n"
    )
    result = run_command(
        [sys.executable, '-c', flooder],
        timeout=5,
        max_bytes=2048,
    )

    assert result.failure == 'output-limit'
    assert result.returncode is None
    # The prefix already captured before the budget was hit must be
    # returned, never discarded.
    assert result.stdout != '' or result.stderr != ''
    assert len(result.stdout) + len(result.stderr) <= 2048


@posix_only
def test_output_limit_detected_even_when_reader_lags_behind_fast_exit(monkeypatch):
    """Regression test for a race in the overflow/exit decision.

    A short-lived child can write past max_bytes and exit before a reader
    thread gets scheduled to process the over-budget chunk. If the
    failure decision is made right when the wait for the child's exit
    returns (instead of after the reader threads have fully drained), the
    run is wrongly reported as a clean 'complete' run with silently
    truncated output. We force this race deterministically by delaying a
    reader thread's processing of each chunk it reads, so the waiter
    thread's "child exited" signal always arrives first.
    """
    def delayed_after_read():
        time.sleep(0.2)

    monkeypatch.setattr(runner, '_after_read', delayed_after_read)

    result = run_command(
        [sys.executable, '-c', "import sys; sys.stdout.write('A' * 4096)"],
        timeout=5,
        max_bytes=1024,
    )

    assert result.failure == 'output-limit'
    assert result.stdout != ''
    assert len(result.stdout) <= 1024


@posix_only
def test_literal_spaces_and_leading_dashes_are_preserved():
    args = ["hello world", "--not-an-option", "-x"]
    result = run_command(
        [sys.executable, '-c', 'import sys; print(repr(sys.argv[1:]))', *args],
        timeout=5,
        max_bytes=65536,
    )

    assert result.failure is None
    assert result.returncode == 0
    assert result.stdout.strip() == repr(args)


@posix_only
def test_nonzero_exit_is_reported():
    result = run_command(
        [sys.executable, '-c', 'import sys; sys.exit(7)'],
        timeout=5,
        max_bytes=1024,
    )

    assert result.failure is None
    assert result.returncode == 7


@posix_only
def test_permission_denied_on_exec_is_explicit(tmp_path):
    script = tmp_path / "no_exec.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o644)  # readable, not executable

    result = run_command([str(script)], timeout=1, max_bytes=1024)

    assert result.failure == 'permission'


@posix_only
def test_invalid_executable_contents_map_to_missing(tmp_path):
    # Exec bit set, but the contents are neither a valid binary nor a
    # shebang script: the OS refuses to exec it (ENOEXEC), which is a
    # plain OSError distinct from FileNotFoundError/PermissionError.
    bad = tmp_path / "not_a_real_binary"
    bad.write_bytes(b"\x00\x01\x02\x03not a real executable")
    bad.chmod(0o755)

    result = run_command([str(bad)], timeout=1, max_bytes=1024)

    assert result.failure == 'missing'
    assert result.stderr != ''  # errno/strerror text reaches the report


@posix_only
def test_cancellation_kills_and_reaps_child(monkeypatch):
    """Simulate KeyboardInterrupt arriving while run_command is waiting.

    We inject the interrupt deterministically through the internal wait
    hook rather than relying on a real signal delivered to the test
    process, and confirm the child was actually killed and reaped (not
    left as a zombie) via a Popen spy.
    """
    created: list[subprocess.Popen] = []
    real_popen = runner.subprocess.Popen

    def spy_popen(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        created.append(proc)
        return proc

    monkeypatch.setattr(runner.subprocess, "Popen", spy_popen)

    def fake_wait_for_event(event, timeout):
        # run_command makes exactly one call to _wait_for_event per
        # invocation, so this always raises -- there is no second call to
        # fall back to a real wait for.
        raise KeyboardInterrupt

    monkeypatch.setattr(runner, "_wait_for_event", fake_wait_for_event)

    start = time.monotonic()
    with pytest.raises(KeyboardInterrupt) as exc_info:
        run_command(
            [sys.executable, '-c', 'import time; time.sleep(5)'],
            timeout=5,
            max_bytes=1024,
        )
    elapsed = time.monotonic() - start

    assert exc_info.value.command_result.failure == 'cancelled'
    # Proves the child was actually killed rather than left to run out its
    # 5s sleep: cleanup returns almost immediately, and the process was
    # terminated by SIGKILL rather than exiting on its own.
    assert elapsed < 3
    assert len(created) == 1
    proc = created[0]
    # poll() returns a non-None exit status only once the child has been
    # reaped; a zombie or still-running process would show None here.
    assert proc.poll() is not None
    assert proc.returncode == -signal.SIGKILL


def test_windows_returns_unavailable_without_starting_anything(monkeypatch):
    monkeypatch.setattr(runner.os, 'name', 'nt')

    result = run_command(['does-not-matter'], timeout=1, max_bytes=1024)

    assert result == CommandResult(None, '', '', 'unavailable')
