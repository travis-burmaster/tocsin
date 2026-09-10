"""Shared pytest fixtures for tests that drive `tocsin.cli.main`."""

from __future__ import annotations

import pytest

import tocsin.cli as cli_module


@pytest.fixture
def force_darwin(monkeypatch):
    """Force `tocsin.cli`'s `platform.system()` to report 'Darwin'.

    `supported_capabilities()` is empty for every platform except
    'Darwin' (Linux/Windows support is a future milestone), so
    `cli._run_scan` reports every scope 'unavailable' and never reaches
    an adapter at all unless the host it runs on identifies as Darwin.
    CI (`.github/workflows/tests.yml`) runs the portable suite on
    macos-latest, ubuntu-latest, and windows-latest: any test that needs
    to exercise real adapter wiring (not the platform-capability gate
    itself) must force Darwin regardless of the actual host running
    pytest, the same lever the unsupported-platform-scope tests already
    use in the other direction (forcing 'Linux' to prove a scope is
    reported unsupported, never silently skipped).

    Also pins `platform.machine()` to 'arm64' so `architecture` in a
    rendered report is deterministic regardless of the CI runner's real
    CPU architecture (Ubuntu/Windows runners are x86_64).
    """
    monkeypatch.setattr(cli_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(cli_module.platform, "machine", lambda: "arm64")
