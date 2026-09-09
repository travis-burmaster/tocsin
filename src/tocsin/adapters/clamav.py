"""Selected-file ClamAV (clamscan) malware scan adapter.

`scan_files` runs `clamscan` against a caller-selected file or directory
and `parse_clamscan_output` turns its `--stdout --infected` text output
into the shared `CheckResult` vocabulary. The engine contract this module
relies on -- verified return codes, flags, and output line format from the
clamscan(1) man page -- is recorded in full in
docs/evidence/clamav-contract.md (research notes in
.superpowers/sdd/2026-09-08-tocsin-implementation/clamav-research.md);
this module implements that contract rather than re-deriving it.

Tocsin enumerates files itself (`os.walk(..., followlinks=False)`, never
`--recursive`) and passes the accepted absolute paths to clamscan via
`--file-list`, so clamscan never walks a directory tree on its own and
never receives a positional path argument. This also lets Tocsin exclude
filenames that would be ambiguous in clamscan's plain-text output (a
control character, or the literal ": " sequence, which is how clamscan
itself separates a path from its verdict) or that are not valid UTF-8 (so
they cannot be written into the file-list at all) -- see
`_ambiguity_reason`.

No engine was available on the development host to pin a tested version
against, so this uses feature detection instead: `clamscan --help` output
is checked for every flag Tocsin passes, and a clamscan lacking
`--alert-exceeds-max` in particular is treated as `unavailable`, because
without it oversized content could be reported clean rather than as a
`Heuristics.Limits.Exceeded` alert. See docs/evidence/clamav-contract.md.

This never passes `--remove`, `--move`, `--copy`, or `--recursive`, and
never downloads or otherwise fetches signatures.
"""

from __future__ import annotations

import os
import re
import shutil
import stat as stat_module
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from tocsin.models import CheckResult, Finding, Runner
from tocsin.runner import run_command

_NAME = 'files'

_VERSION_TIMEOUT = 30
_VERSION_MAX_BYTES = 65536
_HELP_TIMEOUT = 30
_HELP_MAX_BYTES = 262144
_SCAN_TIMEOUT = 300
_SCAN_MAX_BYTES = 16 * 1024 * 1024  # 16 MiB

# Enumeration cap: a module attribute (not a function default) so tests can
# monkeypatch it directly -- scan_files reads this name from the module at
# call time via _enumerate_files's default lookup below.
_MAX_FILES = 100000

_LIMITS = {
    'max_filesize': '100M',
    'max_scansize': '500M',
    'max_recursion': 20,
    'timeout_seconds': _SCAN_TIMEOUT,
    'max_files': _MAX_FILES,
}

# Every flag scan_files passes to clamscan. Checked against `--help` output
# before ever invoking a scan. --alert-exceeds-max is checked first and
# named specifically: without it, oversized content could be reported
# clean instead of alerted.
_ALERT_EXCEEDS_MAX_FLAG = '--alert-exceeds-max'
_OTHER_REQUIRED_FLAGS = (
    '--stdout',
    '--infected',
    '--alert-encrypted',
    '--max-filesize',
    '--max-scansize',
    '--max-recursion',
    '--follow-dir-symlinks',
    '--follow-file-symlinks',
    '--file-list',
)

_RUNNER_FAILURE_TO_COMPLETION = {
    'timeout': 'partial',
    'output-limit': 'partial',
    'cancelled': 'partial',
    'permission': 'error',
}

_VERSION_RE = re.compile(r'^ClamAV\s+([^/\s]+)/([^/\s]+)/(.+)$')

_CONTROL_CHAR_RE = re.compile(r'[\x00-\x1f\x7f]')

_SUMMARY_KEY_MAP = {
    'Known viruses': 'known_viruses',
    'Engine version': 'engine_version',
    'Scanned files': 'scanned_files',
    'Infected files': 'infected_files',
    'Data scanned': 'data_scanned',
    'Data read': 'data_read',
    'Time': 'time',
}

_ERROR_TRIGGERS = ("Can't open file", 'Access denied', 'LibClamAV Error', 'ERROR:')
_MAX_ERROR_LINES = 50
_MAX_ERROR_LINE_LEN = 500


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _escape_control_chars(value: str) -> str:
    """Escape control characters (and DEL) as literal \\xHH so a hostile
    filename cannot alter the terminal or report output. Also escapes a
    lone surrogate code point (0xdc80-0xdcff) the way `os.fsdecode`'s
    'surrogateescape' error handler represents a non-UTF-8 byte from a
    filename, recovering the original byte value, so a non-UTF-8 filename
    can still be named safely in a report string."""
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


def _ambiguity_reason(path_str: str) -> str | None:
    """Why `path_str` cannot be safely submitted to clamscan's `--file-list`,
    or None if it can.

    Three reasons, in the order checked: a control character (including a
    literal newline) or the literal ": " sequence make a
    "<path>: <verdict>" alert line unsplittable/ambiguous; a filename that
    is not valid UTF-8 (surfaced by Python as a string containing a lone
    surrogate, via `os.fsdecode`'s 'surrogateescape' handler) cannot be
    written into the (UTF-8) file-list at all. Tocsin chooses to skip
    such files rather than attempt a lossy surrogateescape round-trip
    through clamscan's own text output, whose encoding behavior for
    non-UTF-8 paths is unverified (no engine was available to check
    against) -- see docs/evidence/clamav-contract.md.
    """
    if _CONTROL_CHAR_RE.search(path_str):
        return 'filename contains a control character, ambiguous in clamscan text output'
    if ': ' in path_str:
        return 'filename contains the ": " sequence, ambiguous in clamscan text output'
    try:
        path_str.encode('utf-8')
    except UnicodeEncodeError:
        return 'filename is not valid UTF-8'
    return None


# --- ParsedScan: the small, runner-free parsing seam ------------------------


@dataclass(frozen=True)
class ParsedScan:
    detections: tuple[Finding, ...]
    heuristics: tuple[Finding, ...]
    skipped: tuple[Finding, ...]
    errors: tuple[str, ...]
    summary: dict[str, object]


def _empty_summary() -> dict[str, object]:
    return {value: None for value in _SUMMARY_KEY_MAP.values()}


def _parse_summary(stdout: str) -> dict[str, object]:
    summary = _empty_summary()
    for line in stdout.splitlines():
        if ':' not in line:
            continue
        key, _, value = line.partition(':')
        key = key.strip()
        mapped = _SUMMARY_KEY_MAP.get(key)
        if mapped is not None:
            summary[mapped] = value.strip()
    return summary


def _files_scanned_from_summary(summary: dict[str, object]) -> int | None:
    """Extract the scanned-file count from a parsed summary dict, or None
    if absent/unparseable."""
    raw = summary.get('scanned_files')
    if raw is None:
        return None
    try:
        return int(str(raw))
    except ValueError:
        return None


def _classify_alert(path_str: str, name: str, observed_at: str) -> tuple[str, Finding]:
    """Classify one alert `name` for `path_str` into a (bucket, Finding) pair.

    bucket is one of 'detections', 'heuristics', 'skipped'.
    """
    if name.startswith('Heuristics.Limits.Exceeded') or name.startswith('Heuristics.Encrypted'):
        return 'skipped', Finding(
            category='file',
            subject=path_str,
            status='skipped',
            severity='unknown',
            confidence='high',
            evidence=(name,),
            action='file exceeded scan limits or is encrypted; inspect manually',
            observed_at=observed_at,
        )
    if name.startswith('Heuristics.'):
        return 'heuristics', Finding(
            category='file',
            subject=path_str,
            status='needs-review',
            severity='unknown',
            confidence='medium',
            evidence=(name,),
            action='review this heuristic alert manually; it is not a confirmed signature match',
            observed_at=observed_at,
        )
    return 'detections', Finding(
        category='file',
        subject=path_str,
        status='detected',
        severity='unknown',
        confidence='high',
        evidence=(name,),
        action='quarantine or delete only after manual confirmation; Tocsin does not modify files',
        observed_at=observed_at,
    )


def _is_summary_line(line: str) -> bool:
    """Whether `line` is part of the trailing SCAN SUMMARY block (its
    banner, or one of the recognized 'Key: value' summary lines) rather
    than a per-file alert or diagnostic."""
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith('---'):
        return True
    key = stripped.split(':', 1)[0].strip()
    return key in _SUMMARY_KEY_MAP


def parse_clamscan_output(stdout: str, stderr: str, requested: list[Path], *,
                           observed_at: str | None = None) -> ParsedScan:
    """Parse `clamscan --stdout --infected` output into a ParsedScan.

    Pure function of the captured text and the set of paths that were
    actually submitted to clamscan (via --file-list): knows nothing about
    exit codes or the runner. An alert line has the shape
    "<absolute path>: <name> FOUND"; because ambiguous paths (containing a
    control character or ": ") were excluded before scanning, each line is
    split with rsplit(': ', 1) after stripping the trailing " FOUND". A
    FOUND line naming a path outside `requested` indicates parse
    ambiguity and is ignored (recorded as an error) rather than trusted.

    `--stdout` redirects clamscan's per-file diagnostics ("Can't open
    file", "Access denied", ...) to stdout alongside the alert lines and
    summary block (clamav-research.md, and this adapter's own --help
    fixture: "Write to stdout instead of stderr"), so every non-FOUND,
    non-blank, non-summary-block stdout line is treated as a diagnostic:
    if it names one of the requested paths (clamscan's per-file
    diagnostics take the shape "<path>: <message>") it becomes an error
    for that path; a line matching a known trigger substring ("Can't open
    file", "Access denied", "LibClamAV Error", "ERROR:") is recorded even
    without a recognizable leading path. stderr is scanned the same way
    for the same trigger substrings, in case a build or wrapper still
    sends diagnostics there. All such lines are recorded as plain error
    strings, bounded to 50 lines of at most 500 characters each --
    clamscan does not emit per-file Finding-worthy structure for these,
    just diagnostic text.
    """
    if observed_at is None:
        observed_at = _now_iso()
    requested_set = {str(p) for p in requested}

    detections: list[Finding] = []
    heuristics: list[Finding] = []
    skipped: list[Finding] = []
    errors: list[str] = []

    for line in stdout.splitlines():
        if not line.strip():
            continue
        if line.endswith(' FOUND'):
            without_found = line[: -len(' FOUND')]
            try:
                path_str, name = without_found.rsplit(': ', 1)
            except ValueError:
                errors.append(f'unparseable clamscan alert line: {line[:_MAX_ERROR_LINE_LEN]}')
                continue
            if path_str not in requested_set:
                errors.append(f'FOUND line named an unrequested path (ignored): {line[:_MAX_ERROR_LINE_LEN]}')
                continue
            bucket, finding = _classify_alert(path_str, name, observed_at)
            if bucket == 'detections':
                detections.append(finding)
            elif bucket == 'heuristics':
                heuristics.append(finding)
            else:
                skipped.append(finding)
            continue
        if _is_summary_line(line):
            continue
        # A non-FOUND, non-summary, non-blank stdout line: with --stdout,
        # clamscan's own per-file diagnostics print here instead of on
        # stderr (see docstring above).
        candidate_path = line.split(': ', 1)[0] if ': ' in line else None
        if candidate_path in requested_set or any(trigger in line for trigger in _ERROR_TRIGGERS):
            errors.append(line.strip()[:_MAX_ERROR_LINE_LEN])

    for line in stderr.splitlines():
        if any(trigger in line for trigger in _ERROR_TRIGGERS):
            errors.append(line.strip()[:_MAX_ERROR_LINE_LEN])

    summary = _parse_summary(stdout)

    return ParsedScan(
        detections=tuple(detections),
        heuristics=tuple(heuristics),
        skipped=tuple(skipped),
        errors=tuple(errors[:_MAX_ERROR_LINES]),
        summary=summary,
    )


# --- engine discovery / feature guard ---------------------------------------


@dataclass
class _EngineProbe:
    path: str | None
    engine: dict[str, object] | None
    ok: bool
    completion: str | None  # only meaningful when ok is False
    error: str | None
    command: list[str] | None


def _parse_version_text(text: str) -> dict[str, object]:
    first_line = ''
    for line in text.splitlines():
        if line.strip():
            first_line = line.strip()
            break
    match = _VERSION_RE.match(first_line)
    if not match:
        return {'name': 'clamav', 'version': None, 'signature_version': None, 'signature_date': None}
    return {
        'name': 'clamav',
        'version': match.group(1),
        'signature_version': match.group(2),
        'signature_date': match.group(3).strip(),
    }


def _missing_required_flag(help_text: str) -> str | None:
    if _ALERT_EXCEEDS_MAX_FLAG not in help_text:
        return _ALERT_EXCEEDS_MAX_FLAG
    for flag in _OTHER_REQUIRED_FLAGS:
        if flag not in help_text:
            return flag
    return None


def _probe_engine(runner: Runner) -> _EngineProbe:
    path = shutil.which('clamscan')
    if path is None:
        return _EngineProbe(None, None, False, 'unavailable', 'clamscan not found on PATH', None)

    version_argv = [path, '--version']
    version_result = runner(version_argv, timeout=_VERSION_TIMEOUT, max_bytes=_VERSION_MAX_BYTES)
    if version_result.failure == 'missing':
        return _EngineProbe(path, None, False, 'unavailable', 'clamscan not found on PATH', version_argv)
    if version_result.failure is not None:
        completion = _RUNNER_FAILURE_TO_COMPLETION.get(version_result.failure, 'error')
        return _EngineProbe(
            path, None, False, completion,
            f'clamscan --version did not complete: {version_result.failure}', version_argv,
        )
    engine_meta = _parse_version_text(version_result.stdout or version_result.stderr)

    help_argv = [path, '--help']
    help_result = runner(help_argv, timeout=_HELP_TIMEOUT, max_bytes=_HELP_MAX_BYTES)
    if help_result.failure == 'missing':
        return _EngineProbe(path, engine_meta, False, 'unavailable', 'clamscan not found on PATH', help_argv)
    if help_result.failure is not None:
        completion = _RUNNER_FAILURE_TO_COMPLETION.get(help_result.failure, 'error')
        return _EngineProbe(
            path, engine_meta, False, completion,
            f'clamscan --help did not complete: {help_result.failure}', help_argv,
        )
    help_text = help_result.stdout or help_result.stderr
    missing_flag = _missing_required_flag(help_text)
    if missing_flag == _ALERT_EXCEEDS_MAX_FLAG:
        return _EngineProbe(
            path, engine_meta, False, 'unavailable',
            'installed clamscan lacks --alert-exceeds-max; oversized content could be reported clean',
            help_argv,
        )
    if missing_flag is not None:
        return _EngineProbe(
            path, engine_meta, False, 'unavailable',
            f'installed clamscan lacks {missing_flag}', help_argv,
        )

    return _EngineProbe(path, engine_meta, True, None, None, None)


def doctor_summary(runner: Runner = run_command) -> str:
    """One-line clamscan status for `tocsin doctor`, reusing the same
    engine/feature probe `scan_files` uses so doctor reports exactly what
    a scan would decide."""
    probe = _probe_engine(runner)
    if probe.path is None:
        return 'not found'
    if not probe.ok:
        return probe.error or 'unavailable'
    engine = probe.engine or {}
    return (
        f"engine {engine.get('version')}, signatures {engine.get('signature_version')} "
        f"({engine.get('signature_date')}), required flags present"
    )


# --- file enumeration --------------------------------------------------------


@dataclass
class _Enumeration:
    accepted: list[Path]
    files_requested: int
    symlinks_skipped: int
    ambiguous_findings: list[Finding]
    other_findings: list[Finding]
    cap_exceeded: bool


def _handle_regular_file(file_path: Path, enum: _Enumeration, *, max_files: int, observed_at: str) -> None:
    if enum.cap_exceeded:
        return
    try:
        st = os.lstat(file_path)
    except OSError as exc:
        enum.other_findings.append(Finding(
            category='file',
            subject=_escape_control_chars(str(file_path)),
            status='skipped',
            severity='unknown',
            confidence='high',
            evidence=(str(exc),),
            action='file could not be read for scanning; verify it exists and is accessible',
            observed_at=observed_at,
        ))
        return
    if stat_module.S_ISLNK(st.st_mode):
        enum.symlinks_skipped += 1
        return
    if not stat_module.S_ISREG(st.st_mode):
        return  # not a plain file (device, socket, ...): not scannable, silently excluded

    if enum.files_requested >= max_files:
        enum.cap_exceeded = True
        return
    enum.files_requested += 1

    path_str = str(file_path)
    reason = _ambiguity_reason(path_str)
    if reason is not None:
        enum.ambiguous_findings.append(Finding(
            category='file',
            subject=_escape_control_chars(path_str),
            status='skipped',
            severity='unknown',
            confidence='high',
            evidence=(reason,),
            action='rename the file to remove ambiguous characters and rescan',
            observed_at=observed_at,
        ))
        return
    enum.accepted.append(file_path)


def _enumerate_files(root: Path, *, max_files: int, observed_at: str | None = None) -> _Enumeration:
    if observed_at is None:
        observed_at = _now_iso()
    enum = _Enumeration(accepted=[], files_requested=0, symlinks_skipped=0, ambiguous_findings=[], other_findings=[], cap_exceeded=False)

    if root.is_file():
        _handle_regular_file(root, enum, max_files=max_files, observed_at=observed_at)
        return enum

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if enum.cap_exceeded:
            break
        kept_dirnames = []
        for dirname in dirnames:
            dir_path = Path(dirpath) / dirname
            try:
                is_link = dir_path.is_symlink()
            except OSError:
                continue
            if is_link:
                enum.symlinks_skipped += 1
                continue
            kept_dirnames.append(dirname)
        dirnames[:] = kept_dirnames

        for filename in filenames:
            if enum.cap_exceeded:
                break
            _handle_regular_file(Path(dirpath) / filename, enum, max_files=max_files, observed_at=observed_at)

    return enum


# --- metadata helpers ---------------------------------------------------------


def _redact_command(argv: list[str]) -> list[str]:
    return ['<file-list>' if arg.startswith('--file-list=') else arg for arg in argv]


def _base_metadata(*, root: Path, engine: dict[str, object] | None = None,
                    command: list[str] | None = None, files_requested: int | None = None,
                    files_scanned: int | None = None, symlinks_skipped: int | None = None,
                    ambiguous_skipped: int | None = None,
                    summary: dict[str, object] | None = None) -> dict[str, object]:
    return {
        'engine': engine or {'name': 'clamav', 'version': None, 'signature_version': None, 'signature_date': None},
        'limits': dict(_LIMITS),
        'summary': summary if summary is not None else _empty_summary(),
        'files_requested': files_requested,
        'files_scanned': files_scanned,
        'symlinks_skipped': symlinks_skipped,
        'ambiguous_skipped': ambiguous_skipped,
        'command': command,
        'root': str(root),
        'coverage': {'assessed': None, 'unassessed': None},
    }


def _drop_trailing_partial_line(text: str) -> str:
    """Drop a possibly-truncated trailing line from output cut short by a
    runner failure (timeout/output-limit/cancelled): if text does not end
    with a newline, whatever follows the last complete newline could be a
    mid-write partial alert line and is discarded rather than
    misparsed."""
    if not text or text.endswith('\n'):
        return text
    idx = text.rfind('\n')
    return text[: idx + 1] if idx != -1 else ''


# --- the adapter entry point --------------------------------------------------


def scan_files(path: Path, *, runner: Runner = run_command, observed_at: str | None = None) -> CheckResult:
    """Scan a caller-selected file or directory with clamscan.

    Enumerates regular files under `path` itself (never following
    symlinks, never letting clamscan recurse), writes the accepted
    absolute paths to a mode-0600 temp file, and invokes clamscan once
    with `--file-list`. See the module docstring and
    docs/evidence/clamav-contract.md for the full contract. `observed_at`
    defaults to the current UTC time when omitted; the CLI passes one run
    timestamp shared by every adapter it calls.
    """
    if observed_at is None:
        observed_at = _now_iso()
    path = Path(path).resolve()

    probe = _probe_engine(runner)
    if not probe.ok:
        return CheckResult(
            name=_NAME,
            completion=probe.completion or 'error',
            findings=(),
            errors=(probe.error or 'clamscan is unavailable',),
            metadata=_base_metadata(root=path, engine=probe.engine, command=probe.command),
        )

    engine_meta = probe.engine

    enumeration = _enumerate_files(path, max_files=_MAX_FILES, observed_at=observed_at)

    findings: list[Finding] = list(enumeration.ambiguous_findings) + list(enumeration.other_findings)
    errors: list[str] = []
    needs_partial = bool(enumeration.ambiguous_findings) or bool(enumeration.other_findings)
    if enumeration.ambiguous_findings:
        errors.append(
            f'{len(enumeration.ambiguous_findings)} file(s) skipped: ambiguous filename '
            '(control character, the ": " sequence, or not valid UTF-8)'
        )
    if enumeration.other_findings:
        errors.append(f'{len(enumeration.other_findings)} file(s) skipped: could not be read for scanning')
    if enumeration.cap_exceeded:
        needs_partial = True
        errors.append(f'enumeration cap of {_MAX_FILES} files reached; stopped enumerating additional files')

    ambiguous_skipped = len(enumeration.ambiguous_findings)
    metadata = _base_metadata(
        root=path,
        engine=engine_meta,
        files_requested=enumeration.files_requested,
        symlinks_skipped=enumeration.symlinks_skipped,
        ambiguous_skipped=ambiguous_skipped,
    )
    metadata['coverage'] = {
        'assessed': enumeration.files_requested - ambiguous_skipped,
        'unassessed': ambiguous_skipped,
    }

    if not enumeration.accepted:
        metadata['files_scanned'] = 0
        completion = 'partial' if needs_partial else 'complete'
        return CheckResult(name=_NAME, completion=completion, findings=tuple(findings), errors=tuple(errors), metadata=metadata)

    fd, tmp_path_str = tempfile.mkstemp(prefix='tocsin-clamav-', suffix='.list')
    try:
        # fdopen first, so `handle` owns `fd` from this point on: if
        # os.fchmod raises, the `with` block's __exit__ still closes the
        # underlying fd (no leak). Every path in `enumeration.accepted`
        # already passed the strict-UTF-8 check in `_ambiguity_reason`,
        # so this write can never raise UnicodeEncodeError.
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            os.fchmod(handle.fileno(), 0o600)
            for accepted_path in enumeration.accepted:
                handle.write(f'{accepted_path}\n')

        argv = [
            probe.path,
            '--stdout',
            '--infected',
            '--alert-exceeds-max=yes',
            '--alert-encrypted=yes',
            f"--max-filesize={_LIMITS['max_filesize']}",
            f"--max-scansize={_LIMITS['max_scansize']}",
            f"--max-recursion={_LIMITS['max_recursion']}",
            '--follow-dir-symlinks=0',
            '--follow-file-symlinks=0',
            f'--file-list={tmp_path_str}',
        ]
        metadata['command'] = _redact_command(argv)

        result = runner(argv, timeout=_SCAN_TIMEOUT, max_bytes=_SCAN_MAX_BYTES)
    finally:
        try:
            os.remove(tmp_path_str)
        except OSError:
            pass

    if result.failure == 'missing':
        return CheckResult(
            name=_NAME, completion='unavailable', findings=tuple(findings),
            errors=tuple(errors) + ('clamscan not found on PATH',), metadata=metadata,
        )

    if result.failure in ('timeout', 'output-limit', 'cancelled'):
        stdout = _drop_trailing_partial_line(result.stdout)
        parsed = parse_clamscan_output(stdout, result.stderr, enumeration.accepted, observed_at=observed_at)
        findings += list(parsed.detections) + list(parsed.heuristics) + list(parsed.skipped)
        errors += list(parsed.errors)
        errors.append(f'clamscan did not complete: {result.failure}')
        metadata['summary'] = parsed.summary
        metadata['files_scanned'] = _files_scanned_from_summary(parsed.summary)
        return CheckResult(name=_NAME, completion='partial', findings=tuple(findings), errors=tuple(errors), metadata=metadata)

    if result.failure == 'permission':
        errors.append('clamscan did not complete: permission')
        return CheckResult(name=_NAME, completion='error', findings=tuple(findings), errors=tuple(errors), metadata=metadata)

    if result.failure is not None:
        errors.append(f'clamscan did not complete: {result.failure}')
        return CheckResult(name=_NAME, completion='error', findings=tuple(findings), errors=tuple(errors), metadata=metadata)

    rc = result.returncode
    parsed = parse_clamscan_output(result.stdout, result.stderr, enumeration.accepted, observed_at=observed_at)
    metadata['summary'] = parsed.summary
    metadata['files_scanned'] = _files_scanned_from_summary(parsed.summary)

    has_found_lines = bool(parsed.detections or parsed.heuristics or parsed.skipped)

    if rc == 2 and not has_found_lines:
        # "some error(s) occurred" and nothing was parsed at all (e.g. a
        # missing signature database): never invent a clean/no-match
        # finding here -- report a plain failure with zero PARSED alert
        # findings. Enumeration-time findings/errors (ambiguous names,
        # stat failures, the enumeration cap) are still retained: "exit
        # 2: partial or failed, retaining any findings" applies to those
        # even though the scan attempt itself produced nothing usable.
        detail = result.stderr.strip() or '(no stderr)'
        combined_errors = tuple(errors) + tuple(parsed.errors) + (f'clamscan exited 2: {detail}',)
        return CheckResult(
            name=_NAME, completion='error', findings=tuple(findings),
            errors=combined_errors, metadata=metadata,
        )

    if rc == 2:
        completion = 'partial'
        errors.append('clamscan exited 2 (some errors occurred); keeping the alerts it did parse')
    elif rc in (0, 1):
        completion = 'partial' if (needs_partial or parsed.skipped or parsed.errors) else 'complete'
    else:
        detail = result.stderr.strip() or '(no stderr)'
        combined_errors = tuple(errors) + tuple(parsed.errors) + (f'clamscan exited {rc}: {detail}',)
        return CheckResult(
            name=_NAME, completion='error', findings=tuple(findings),
            errors=combined_errors, metadata=metadata,
        )

    findings += list(parsed.detections) + list(parsed.heuristics) + list(parsed.skipped)
    errors += list(parsed.errors)

    return CheckResult(name=_NAME, completion=completion, findings=tuple(findings), errors=tuple(errors), metadata=metadata)
