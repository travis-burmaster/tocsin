"""Argument parsing and orchestration for the tocsin command-line tool."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys
from pathlib import Path

from tocsin.adapters.clamav import doctor_summary as clamav_doctor_summary
from tocsin.adapters.clamav import scan_files
from tocsin.adapters.osv import scan_project, version_compatibility
from tocsin.kb import kb_snapshot
from tocsin.models import CheckResult, Runner
from tocsin.platforms import supported_capabilities
from tocsin.platforms.macos import inventory_brew
from tocsin.platforms.macos_posture import scan_posture
from tocsin.report import exit_code, render_json, render_text
from tocsin.runner import run_command

# Engines doctor looks for on PATH, without installing anything. Reported
# per-tool as "not found", a failure kind, or the first line of its
# `--version` output. Later tasks pin and validate specific versions; this
# is discovery only.
_ENGINE_EXECUTABLES = ("brew", "clamscan", "osv-scanner")

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

    doctor = subparsers.add_parser(
        "doctor",
        help="Report host platform, Python version, and engine availability.",
    )
    doctor.add_argument("--kb", metavar="PATH", help="Report readability of a local knowledge-base checkout.")

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
    scan.add_argument(
        "--osv-database",
        metavar="PATH",
        help=(
            "Offline alternative to --online for --project: a local directory "
            "already populated as OSV-Scanner's OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY "
            "layout (<PATH>/osv-scalibr/<Ecosystem>/all.zip). Without --online, "
            "--project requires this."
        ),
    )
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


def _first_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return "(no output)"


def _report_engine(name: str, runner: Runner = run_command) -> str:
    """Report one engine's discovery state without installing anything.

    Returns "not found" if the executable is absent from PATH; otherwise
    runs `<name> --version` through the bounded runner and reports either
    the failure kind or the first non-blank line of its output. This does
    not judge version compatibility; later tasks pin versions.
    """
    path = shutil.which(name)
    if path is None:
        return "not found"
    result = runner([path, "--version"], timeout=10, max_bytes=65536)
    if result.failure is not None:
        return f"error: {result.failure}"
    return _first_line(result.stdout or result.stderr)


def _run_doctor(*, kb: str | None = None, runner: Runner = run_command) -> int:
    system = platform.system()
    print(f"platform: {system} ({platform.machine()})")
    print(f"python: {platform.python_version()}")

    capabilities = supported_capabilities(system)
    print(f"capabilities: {', '.join(sorted(capabilities)) if capabilities else 'none integrated yet'}")

    for name in _ENGINE_EXECUTABLES:
        if name == "clamscan":
            # Reuses the same engine/feature probe scan_files uses, so
            # doctor reports exactly what a --files scan would decide
            # (engine/signature version and date, and required-flag support)
            # rather than just the raw --version line.
            print(f"{name}: {clamav_doctor_summary(runner=runner)}")
            continue
        line = _report_engine(name, runner=runner)
        if name == "osv-scanner" and line.startswith("osv-scanner version:"):
            line = f"{line} -- {version_compatibility(line)}"
        print(f"{name}: {line}")

    if kb is not None:
        kb_root = Path(kb)
        exists = kb_root.exists()
        print(f"kb: {kb_root} ({'found' if exists else 'not found'})")
        if exists:
            snapshot = kb_snapshot(kb_root)
            print(f"kb commit: {snapshot.get('commit')}")

    return 0


def _scope_requested(args: argparse.Namespace, name: str) -> bool:
    value = getattr(args, name)
    return value if name in _SCAN_BOOL_SCOPES else value is not None


def _run_scan(args: argparse.Namespace, *, runner: Runner = run_command) -> int:
    requested_scopes = [name for name in _SCAN_SCOPE_ORDER if _scope_requested(args, name)]
    if not requested_scopes:
        print(
            "error: scan requires at least one of --brew, --files, --project, --posture",
            file=sys.stderr,
        )
        return 2

    system = platform.system()
    capabilities = supported_capabilities(system)

    def _unavailable_reason(scope: str) -> str:
        # Never silently ignore a requested scope: distinguish a platform
        # that cannot support this scope at all from one where the scope
        # is possible but its adapter is not wired up yet.
        if scope not in capabilities:
            return f"{scope} is not supported on this platform ({system})"
        return f"the {scope} adapter is not integrated yet"

    results: list[CheckResult] = []
    for scope in requested_scopes:
        if scope == "brew" and scope in capabilities:
            kb_root = Path(args.kb) if args.kb else None
            results.append(inventory_brew(kb_root=kb_root, runner=runner))
            continue
        if scope == "files" and scope in capabilities:
            files_path = Path(args.files)
            if not files_path.exists():
                results.append(CheckResult(
                    name="files",
                    completion="error",
                    findings=(),
                    errors=(f"--files path does not exist: {files_path}",),
                    metadata={},
                ))
                continue
            results.append(scan_files(files_path.resolve(), runner=runner))
            continue
        if scope == "posture" and scope in capabilities:
            results.append(scan_posture(runner=runner))
            continue
        if scope == "project" and scope in capabilities:
            project_path = Path(args.project)
            if not project_path.is_dir():
                results.append(CheckResult(
                    name="project",
                    completion="error",
                    findings=(),
                    errors=(f"--project path does not exist or is not a directory: {project_path}",),
                    metadata={},
                ))
                continue
            kb_root = Path(args.kb) if args.kb else None
            database = Path(args.osv_database) if args.osv_database else None
            results.append(scan_project(
                project_path.resolve(),
                online=args.online,
                database=database,
                kb_root=kb_root,
                runner=runner,
            ))
            continue
        results.append(CheckResult(
            name=scope,
            completion="unavailable",
            findings=(),
            errors=(_unavailable_reason(scope),),
            metadata={},
        ))

    context = {
        "generated_at": None,
        "platform": system,
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


def main(argv: list[str] | None = None, *, runner: Runner = run_command) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        return int(code)

    if args.command == "doctor":
        return _run_doctor(kb=args.kb, runner=runner)
    if args.command == "scan":
        return _run_scan(args, runner=runner)

    # argparse's subparsers(required=True) makes this unreachable.
    print(f"error: unknown command: {args.command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
