"""Argument parsing and orchestration for the tocsin command-line tool."""

from __future__ import annotations

import argparse
import os
import platform
import sys

from tocsin.models import CheckResult
from tocsin.report import exit_code, render_json, render_text

# Scan scopes, in the order they are reported. --brew and --posture are
# boolean store_true flags; --files and --project take a PATH, where even an
# empty string still counts as requested (checked via "is not None").
_SCAN_BOOL_SCOPES = frozenset({"brew", "posture"})
_SCAN_SCOPE_ORDER = ("brew", "files", "project", "posture")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tocsin", description=(
        "Evidence-based security scanner for malware, known software "
        "vulnerabilities, and operating-system security posture."
    ))
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "doctor",
        help="Report host platform, Python version, and engine availability.",
    )

    scan = subparsers.add_parser("scan", help="Run one or more scan scopes.")
    scan.add_argument("--brew", action="store_true", help="Inventory Homebrew packages and posture.")
    scan.add_argument("--files", metavar="PATH", help="Scan selected files or a selected folder.")
    scan.add_argument("--project", metavar="PATH", help="Check project dependencies for known vulnerabilities.")
    scan.add_argument("--posture", action="store_true", help="Check macOS security configuration and startup entries.")
    scan.add_argument("--kb", metavar="PATH", help="Optional local knowledge-base checkout for package context.")
    scan.add_argument(
        "--online",
        action="store_true",
        help=(
            "Allow online advisory lookups. Package names and versions may "
            "be transmitted to advisory services."
        ),
    )
    scan.add_argument("--osv-database", metavar="PATH", help="Local OSV database for offline dependency checks.")
    scan.add_argument("--format", choices=("text", "json"), default="text", help="Report format (default: text).")
    scan.add_argument("--output", metavar="PATH", help="Write the report to PATH instead of stdout.")
    scan.add_argument("--overwrite", action="store_true", help="Allow replacing an existing --output file.")

    return parser


def _write_output(path: str, content: str, overwrite: bool) -> bool:
    """Create PATH exclusively (mode 0600) and write content.

    Returns False without writing anything if PATH already exists and
    overwrite is False. Always leaves the file at mode 0600.
    """
    flags = os.O_CREAT | os.O_WRONLY
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, 0o600)
    return True


def _run_doctor() -> int:
    print(f"platform: {platform.system()} ({platform.machine()})")
    print(f"python: {platform.python_version()}")
    print("engines: none integrated yet")
    return 0


def _scope_requested(args: argparse.Namespace, name: str) -> bool:
    value = getattr(args, name)
    return value if name in _SCAN_BOOL_SCOPES else value is not None


def _run_scan(args: argparse.Namespace) -> int:
    requested_scopes = [name for name in _SCAN_SCOPE_ORDER if _scope_requested(args, name)]
    if not requested_scopes:
        print(
            "error: scan requires at least one of --brew, --files, --project, --posture",
            file=sys.stderr,
        )
        return 2

    results: list[CheckResult] = [
        CheckResult(
            name=scope,
            completion="unavailable",
            findings=(),
            errors=(f"the {scope} adapter is not integrated yet",),
            metadata={},
        )
        for scope in requested_scopes
    ]

    context = {
        "generated_at": None,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "requested_scopes": requested_scopes,
    }

    code = exit_code(results)
    content = render_json(results, context) if args.format == "json" else render_text(results, context)

    if args.output:
        written = _write_output(args.output, content, args.overwrite)
        if not written:
            print(
                f"error: {args.output} already exists; pass --overwrite to replace it",
                file=sys.stderr,
            )
            return 2
    else:
        sys.stdout.write(content)

    return code


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        return int(code)

    if args.command == "doctor":
        return _run_doctor()
    if args.command == "scan":
        return _run_scan(args)

    # argparse's subparsers(required=True) makes this unreachable.
    print(f"error: unknown command: {args.command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
