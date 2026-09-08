"""Shared data model for Tocsin: identities, findings, and adapter outcomes.

These dataclasses are the common vocabulary used by every adapter, the
runner, and the report/CLI layers. See shared-contracts.md for the
authoritative definitions this module implements.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    provenance: dict[str, str]


@dataclass(frozen=True)
class Finding:
    category: str
    subject: str
    status: str  # detected, needs-review, no-known-match, unassessed, skipped, error
    severity: str
    confidence: str
    evidence: tuple[str, ...]
    action: str
    observed_at: str


@dataclass(frozen=True)
class CheckResult:
    name: str
    completion: str  # complete, partial, unavailable, error
    findings: tuple[Finding, ...]
    errors: tuple[str, ...]
    metadata: dict[str, object]
    # Invariant: a result containing any finding with status 'error' or
    # 'skipped' must not have completion 'complete'. exit_code enforces this
    # defensively; adapters must also set partial themselves.


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    stdout: str
    stderr: str
    failure: str | None  # missing, timeout, cancelled, output-limit, permission


# Signature of run_command (defined in tocsin.runner, added in a later task).
Runner = Callable[..., CommandResult]
