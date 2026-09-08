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


def _after_read() -> None:
    """No-op hook called by a reader thread right after os.read() returns.

    Exists purely so tests can inject a deterministic delay here, forcing
    the race between a reader thread noticing an over-budget chunk and the
    waiter thread noticing the child already exited -- the exact race the
    post-join, authoritative overflow check in run_command guards against.
    """
    return None


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
            _after_read()
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
    except OSError as exc:
        # Anything else the OS refuses to exec (e.g. ENOEXEC "Exec format
        # error" for a file with the executable bit set but invalid
        # contents). The executable cannot be run as one either way; keep
        # the errno/strerror text so it reaches the report.
        return CommandResult(None, "", str(exc), "missing")

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

    cancelled_interrupt: KeyboardInterrupt | None = None
    triggered = False

    try:
        try:
            triggered = _wait_for_event(wake, timeout)
        except KeyboardInterrupt as interrupt:
            # Cleanup (kill/join/reap/close) happens in the finally below,
            # exactly once, on every path -- this handler's only job is to
            # remember that cancellation is what happened.
            cancelled_interrupt = interrupt
    finally:
        # Kill the whole process group only if it might still be running:
        # proc.poll() is a non-blocking check that returns the cached
        # returncode without touching the OS again once the waiter thread
        # has already reaped the child, so this avoids sending a signal to
        # a pid the kernel could since have reused for an unrelated
        # process. When the child is still alive (real timeout,
        # cancellation, or overflow detected while it was still running),
        # killing it here is what makes the join below terminate promptly
        # instead of waiting out its bounded grace period, by unblocking
        # reader threads stuck in a blocking read() on a pipe the child
        # has stalled writing into.
        if proc.poll() is None:
            _kill_process_group(proc)
        _join_all(waiter_thread, stdout_thread, stderr_thread)
        # proc.wait() blocks until the child actually exits; the kill just
        # above guarantees that happens quickly, so this never hangs and
        # always reaps -- no zombie survives run_command on any path.
        _reap(proc)
        try:
            proc.stdout.close()
        except Exception:
            pass
        try:
            proc.stderr.close()
        except Exception:
            pass

    # Authoritative failure decision, taken only now that every reader
    # thread has fully drained (joined above). A short-lived child can
    # write past max_bytes and exit before a reader thread gets scheduled
    # to process the over-budget chunk, racing ahead of the child's exit
    # signal; budget.overflowed is only trustworthy once draining is done.
    if cancelled_interrupt is not None:
        failure = "cancelled"
    elif budget.overflowed:
        failure = "output-limit"
    elif not triggered:
        failure = "timeout"
    else:
        failure = None

    returncode = proc.returncode if failure is None else None
    stdout_text = _decode(stdout_reader.result())
    stderr_text = _decode(stderr_reader.result())

    if cancelled_interrupt is not None:
        # Re-raise the same interrupt (preserving its identity/traceback)
        # after cleanup, with the cancelled CommandResult attached so
        # callers/tests can inspect what was captured before the kill.
        cancelled_interrupt.command_result = CommandResult(None, stdout_text, stderr_text, "cancelled")
        raise cancelled_interrupt

    return CommandResult(returncode, stdout_text, stderr_text, failure)
