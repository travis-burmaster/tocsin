"""Cross-cutting helpers shared by the CLI, the adapters, and the report.

Three things every layer needs and none of them owns: the one timestamp
format Tocsin writes, the one mapping from the bounded runner's failure
vocabulary to a `CheckResult` completion, and the one control-character
escaping rule applied to anything that reaches a terminal. Each of these
had been copied into several modules; a divergent copy of any of them is
a correctness bug (an adapter that maps a failure differently, or a
report path that escapes less than another), so they live here instead.
"""

from __future__ import annotations

from datetime import datetime, timezone

# Bounded-runner failure kind -> CheckResult completion. A failure kind
# absent from this map has no agreed meaning and callers treat it as
# 'error' (`.get(failure, 'error')`); 'missing' is deliberately not here,
# because an absent engine is 'unavailable' only in the adapters that
# probe for it and each decides that for itself.
RUNNER_FAILURE_TO_COMPLETION = {
    'timeout': 'partial',
    'output-limit': 'partial',
    'cancelled': 'partial',
    'permission': 'error',
    'unavailable': 'unavailable',
}


def now_iso() -> str:
    """The current UTC time in the single format Tocsin writes."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def escape_control_chars(value: str) -> str:
    """Escape control characters (and DEL) as literal \\xHH so a hostile
    filename, engine string, or advisory field cannot alter the terminal
    or the report output. Also escapes a lone surrogate code point
    (0xdc80-0xdcff) the way `os.fsdecode`'s 'surrogateescape' error
    handler represents a non-UTF-8 byte from a filename, recovering the
    original byte value, so a non-UTF-8 filename can still be named
    safely in a report string. Everything else, including non-ASCII
    printable text, is passed through unchanged."""
    out = []
    for ch in value:
        code_point = ord(ch)
        if code_point < 0x20 or code_point == 0x7f:
            out.append(f'\\x{code_point:02x}')
        elif 0xdc80 <= code_point <= 0xdcff:
            out.append(f'\\x{code_point - 0xdc00:02x}')
        else:
            out.append(ch)
    return ''.join(out)
