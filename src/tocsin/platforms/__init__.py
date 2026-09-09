"""Platform capability selection.

`supported_capabilities` tells the CLI which scan scopes make sense to even
attempt on the current host, independent of whether the underlying adapter
or external engine is actually installed. Adapters are integrated
incrementally (Tasks 3, 4, 6, 7 add 'brew', 'project', 'files', 'posture'
for 'Darwin'); until an adapter lands, its name must not appear here for
any platform, so a requested scope on an unsupported platform is reported
as unsupported rather than silently attempted or ignored.
"""

from __future__ import annotations

# Keyed by the value of platform.system(): 'Darwin', 'Linux', 'Windows'.
# Adding a capability as its adapter lands is a one-line change to the
# relevant frozenset below.
_CAPABILITIES_BY_SYSTEM: dict[str, frozenset[str]] = {
    "Darwin": frozenset({"brew", "project", "files", "posture"}),
    "Linux": frozenset(),
    "Windows": frozenset(),
}


def supported_capabilities(system: str) -> frozenset[str]:
    """Return the scan capability names available on `system`.

    `system` is the value of `platform.system()`. Platforms with no entry
    (or no integrated adapters yet) return an empty frozenset.
    """
    return _CAPABILITIES_BY_SYSTEM.get(system, frozenset())
