"""Report rendering (text and JSON) and the scan exit-code policy."""

from __future__ import annotations

import json

from tocsin.models import CheckResult, Finding

INCOMPLETE_STATUSES = {'error', 'skipped'}
ACTIONABLE_STATUSES = {'detected', 'needs-review'}


def exit_code(results: list[CheckResult]) -> int:
    """Map a set of check results to a process exit code.

    0: every requested check completed with no actionable findings.
    1: every requested check completed, with actionable findings.
    2: at least one check was incomplete (not 'complete', or carrying an
       'error'/'skipped' finding), regardless of findings elsewhere.
    """
    if any(r.completion != 'complete' for r in results):
        return 2
    if any(f.status in INCOMPLETE_STATUSES for r in results for f in r.findings):
        return 2
    if any(f.status in ACTIONABLE_STATUSES for r in results for f in r.findings):
        return 1
    return 0


def _escape_control_chars(value: str) -> str:
    """Escape control characters so hostile strings cannot alter the terminal.

    Every character below 0x20, plus DEL (0x7f), is rendered as a literal
    \\xHH escape. Everything else, including non-ASCII printable text, is
    passed through unchanged.
    """
    out = []
    for ch in value:
        code_point = ord(ch)
        if code_point < 0x20 or code_point == 0x7f:
            out.append(f"\\x{code_point:02x}")
        else:
            out.append(ch)
    return "".join(out)


def _finding_to_dict(finding: Finding) -> dict[str, object]:
    return {
        "category": finding.category,
        "subject": finding.subject,
        "status": finding.status,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence": list(finding.evidence),
        "action": finding.action,
        "observed_at": finding.observed_at,
    }


def _result_to_dict(result: CheckResult) -> dict[str, object]:
    return {
        "name": result.name,
        "completion": result.completion,
        "findings": [_finding_to_dict(f) for f in result.findings],
        "errors": list(result.errors),
        "metadata": result.metadata,
    }


def render_json(results: list[CheckResult], context: dict[str, object]) -> str:
    """Render results as a JSON report string.

    `context` supplies report-level metadata that is not derivable from the
    results themselves: `generated_at` (UTC ISO-8601 string, or None if
    unknown), `platform`/`architecture` (host identity, or None if
    unknown), and `requested_scopes` (the scan scopes the user asked for).
    """
    payload = {
        "schema_version": "1",
        "generated_at": context.get("generated_at"),
        "host": {
            "platform": context.get("platform"),
            "architecture": context.get("architecture"),
        },
        "requested_scopes": list(context.get("requested_scopes", [])),
        "results": [_result_to_dict(r) for r in results],
    }
    return json.dumps(payload, indent=2) + "\n"


def _coverage_line(metadata: dict[str, object]) -> str | None:
    """Build a compact 'coverage: ...' summary line, or None if there's nothing to show.

    Metadata is otherwise invisible in the text report; this surfaces the
    facts a reader most often wants without restructuring the renderer:
    assessed/unassessed counts and the KB's status (its commit when a
    readable KB was used, or why it wasn't when not).
    """
    if not isinstance(metadata, dict):
        return None
    parts: list[str] = []
    coverage = metadata.get('coverage')
    if isinstance(coverage, dict):
        parts.append(f"assessed={coverage.get('assessed')} unassessed={coverage.get('unassessed')}")
    kb_info = metadata.get('kb')
    if isinstance(kb_info, dict):
        status = kb_info.get('status')
        if status == 'available':
            commit = kb_info.get('commit')
            parts.append(f"kb_commit={_escape_control_chars(commit) if commit else 'none'}")
        elif status == 'unreadable':
            parts.append('kb=unreadable')
    if not parts:
        return None
    return "coverage: " + ", ".join(parts)


def render_text(results: list[CheckResult], context: dict[str, object]) -> str:
    """Render results as a human-readable report, one section per check."""
    lines: list[str] = []
    scopes = ", ".join(_escape_control_chars(s) for s in context.get("requested_scopes", []))
    lines.append(f"Tocsin scan report (scopes: {scopes or 'none'})")
    lines.append("")

    for result in results:
        lines.append(f"== {_escape_control_chars(result.name)} [{result.completion}] ==")
        if result.errors:
            for error in result.errors:
                lines.append(f"  error: {_escape_control_chars(error)}")
        if not result.findings:
            lines.append("  no findings")
        for finding in result.findings:
            subject = _escape_control_chars(finding.subject)
            lines.append(
                f"  - [{finding.status}] {subject} "
                f"(severity={finding.severity}, confidence={finding.confidence})"
            )
            lines.append(f"      action: {_escape_control_chars(finding.action)}")
            for evidence in finding.evidence:
                lines.append(f"      evidence: {_escape_control_chars(evidence)}")
        coverage_line = _coverage_line(result.metadata)
        if coverage_line:
            lines.append(f"  {coverage_line}")
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"
