"""Bounded subprocess invocation.

`run_command` is the single boundary every adapter uses to invoke an
external tool (Homebrew, OSV-Scanner, ClamAV, macOS posture commands, ...).
It never runs a shell, never inherits the caller's environment wholesale,
and always bounds both the wall-clock time and the combined bytes of
output a child can produce before it is killed. See shared-contracts.md
for the authoritative contract this module implements.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading

from tocsin.models import CommandResult

# Environment variables copied from the parent process into the child's
# minimal environment. Everything else -- including HOMEBREW_*, DYLD_*, and
# LD_* variables that could redirect a security tool's behavior -- is
# dropped. LANG defaults to C.UTF-8 when the parent does not set it.
_INHERITED_ENV_KEYS = ("PATH", "HOME", "TMPDIR", "LANG")
_DEFAULT_LANG = "C.UTF-8"

# Size of each read() call against a child's stdout/stderr pipe.
_CHUNK_SIZE = 65536

# Bounded join()/wait() grace periods used only during cleanup, after the
# child has already been killed or has already exited. These exist purely
# as a safety net against a hang; they are not part of the timeout/max_bytes
# contract.
_CLEANUP_JOIN_SECONDS = 2.0


def _build_env(extra_env: dict[str, str] | None) -> dict[str, str]:
    """Build a minimal child environment: PATH/HOME/TMPDIR/LANG, plus overlay."""
    env = {key: os.environ[key] for key in _INHERITED_ENV_KEYS if key in os.environ}
    env.setdefault("LANG", _DEFAULT_LANG)
    if extra_env:
        env.update(extra_env)
    return env


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Kill the process group rooted at proc (started with start_new_session=True)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass  # already gone, or we never had permission to signal it


def _reap(proc: subprocess.Popen) -> None:
    """Wait for proc so it never remains a zombie. Safe to call more than once."""
    try:
        proc.wait()
    except Exception:
        pass


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _wait_for_event(event: threading.Event, timeout: float) -> bool:
    """Thin wrapper around Event.wait so tests can inject cancellation here."""
    return event.wait(timeout)


class _Budget:
    """A combined byte budget shared by the stdout and stderr readers."""

    def __init__(self, max_bytes: int, wake: threading.Event) -> None:
        self._max_bytes = max_bytes
        self._used = 0
        self._lock = threading.Lock()
        self._wake = wake
        self._overflowed = False

    def consume(self, n: int) -> int:
        """Reserve up to n bytes of budget; return how many were granted.

        If fewer than n bytes are granted, the budget is exhausted: marks
        the budget overflowed and wakes anyone waiting on it.
        """
        with self._lock:
            remaining = self._max_bytes - self._used
            allowed = min(n, max(remaining, 0))
            self._used += allowed
            if allowed < n:
                self._overflowed = True
                self._wake.set()
            return allowed

    @property
    def overflowed(self) -> bool:
        return self._overflowed


class _StreamReader:
    """Drains one pipe into memory, respecting a shared combined budget."""

    def __init__(self, stream, budget: _Budget) -> None:
        self._stream = stream
        self._budget = budget
        self._chunks: list[bytes] = []

    def run(self) -> None:
        fd = self._stream.fileno()
        while True:
            try:
                data = os.read(fd, _CHUNK_SIZE)
            except OSError:
                break
            if not data:
                break  # EOF: writer end closed
            allowed = self._budget.consume(len(data))
            if allowed:
                self._chunks.append(data[:allowed])
            if allowed < len(data):
                break  # budget exhausted; stop draining this stream

    def result(self) -> bytes:
        return b"".join(self._chunks)


def _join_all(*threads: threading.Thread) -> None:
    for thread in threads:
        thread.join(timeout=_CLEANUP_JOIN_SECONDS)


def run_command(
    argv: list[str],
    *,
    timeout: float,
    max_bytes: int,
    extra_env: dict[str, str] | None = None,
) -> CommandResult:
    """Run argv as a child process, bounded by timeout and max_bytes.

    Never uses a shell; argv is passed straight to the OS with no
    interpolation. The child gets a minimal environment (see _build_env),
    runs in its own process group, and is killed (whole group) on timeout,
    combined-output overflow, or cancellation. See the module docstring and
    shared-contracts.md for the full failure vocabulary and behavior.
    """
    if os.name != "posix":
        # No process-group semantics to build on outside POSIX yet; refuse
        # to start anything rather than run unbounded.
        return CommandResult(None, "", "", "unavailable")

    env = _build_env(extra_env)

    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=env,
            start_new_session=True,
        )
    except FileNotFoundError:
        return CommandResult(None, "", "", "missing")
    except NotADirectoryError:
        return CommandResult(None, "", "", "missing")
    except PermissionError:
        return CommandResult(None, "", "", "permission")

    wake = threading.Event()
    budget = _Budget(max_bytes, wake)
    stdout_reader = _StreamReader(proc.stdout, budget)
    stderr_reader = _StreamReader(proc.stderr, budget)
    stdout_thread = threading.Thread(target=stdout_reader.run, daemon=True)
    stderr_thread = threading.Thread(target=stderr_reader.run, daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    def _waiter() -> None:
        proc.wait()
        wake.set()

    waiter_thread = threading.Thread(target=_waiter, daemon=True)
    waiter_thread.start()

    try:
        triggered = _wait_for_event(wake, timeout)
    except KeyboardInterrupt as interrupt:
        _kill_process_group(proc)
        _join_all(waiter_thread, stdout_thread, stderr_thread)
        _reap(proc)
        stdout_text = _decode(stdout_reader.result())
        stderr_text = _decode(stderr_reader.result())
        try:
            proc.stdout.close()
            proc.stderr.close()
        except Exception:
            pass
        # Re-raise the same interrupt (preserving its identity/traceback)
        # after cleanup, with the cancelled CommandResult attached so
        # callers/tests can inspect what was captured before the kill.
        interrupt.command_result = CommandResult(None, stdout_text, stderr_text, "cancelled")
        raise

    if budget.overflowed:
        _kill_process_group(proc)
        failure = "output-limit"
    elif not triggered:
        _kill_process_group(proc)
        failure = "timeout"
    else:
        failure = None  # exited on its own, without overflowing the budget

    _join_all(waiter_thread, stdout_thread, stderr_thread)
    _reap(proc)  # idempotent; guarantees no zombie even on unexpected paths

    returncode = proc.returncode if failure is None else None
    stdout_text = _decode(stdout_reader.result())
    stderr_text = _decode(stderr_reader.result())
    try:
        proc.stdout.close()
        proc.stderr.close()
    except Exception:
        pass

    return CommandResult(returncode, stdout_text, stderr_text, failure)
