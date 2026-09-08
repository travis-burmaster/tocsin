"""Local OSS Security KB context extraction.

Reads Markdown package pages from a user-supplied, read-only KB checkout
and extracts a small, structured summary (status, dates, audits,
advisories) for one package at a time. Markdown content is treated as
untrusted text: this module never follows links, never executes anything,
and never runs `git` (or any other subprocess) against the KB checkout --
a KB-local `.git/config` can set `core.fsmonitor` or `core.hooksPath` to
run arbitrary programs, so `kb_snapshot` reads Git's plumbing files
directly instead of invoking the `git` binary.
"""

from __future__ import annotations

import re
from pathlib import Path

from tocsin.models import Package

# Ecosystem -> directory (relative to the KB root) holding its package
# pages. Unknown ecosystems are reported as such rather than guessed at.
_ECOSYSTEM_PAGES: dict[str, str] = {
    'homebrew': 'wiki/homebrew',
    'npm': 'wiki/npm',
    'python': 'wiki/python',
    'rust': 'wiki/rust',
    'go': 'wiki/go',
    'dotnet': 'wiki/dotnet',
    'linux': 'wiki/linux',
    'kubernetes': 'wiki/kubernetes',
}

# Explicit (ecosystem, package name) -> page-name overrides, checked before
# the derived name below. The KB has no scoped npm pages yet, so this is
# intentionally empty in production; tests populate it with a
# fixture-only alias to prove the lookup path works.
ALIASES: dict[tuple[str, str], str] = {}

# A resolved page name may contain only these characters: no path
# separators, no "..", nothing that could be interpreted as a traversal
# sequence once joined onto the KB root.
_PAGE_NAME_RE = re.compile(r'^[A-Za-z0-9._@+-]+$')

# Bound how much of a KB page we will ever read into memory.
_MAX_PAGE_BYTES = 1024 * 1024  # 1 MiB

# Bounds for the Git plumbing files kb_snapshot reads directly.
_MAX_HEAD_BYTES = 4096
_MAX_REF_BYTES = 4096
_MAX_PACKED_REFS_BYTES = 1024 * 1024

_COMMIT_RE = re.compile(r'^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$')
_REF_RE = re.compile(r'^refs/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)*$')

_HEADING_RE = re.compile(r'^#\s+(.+)$', re.MULTILINE)
_STATUS_RE = re.compile(r'\*\*Current Status:\*\*\s*(.+)')
_REPOSITORY_RE = re.compile(r'\*\*Repository:\*\*\s*(.+)')
_LAST_UPDATED_RE = re.compile(r'\*Last updated:\s*(\d{4}-\d{2}-\d{2})')
_DATE_CELL_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_ADVISORY_ID_RE = re.compile(r'^[\w.\-]+$')
_TABLE_SEPARATOR_RE = re.compile(r'^:?-{2,}:?$')

_KB_SOURCE_REPO = 'https://github.com/travis-burmaster/oss-security-kb'

# Attribution for the OSS Security KB, attached once per report (not per
# package) in metadata['kb'] whenever a readable KB checkout is in use.
# Shared by every adapter that reports package-level KB context (Homebrew,
# OSV) so the attribution block is defined in exactly one place.
_KB_LICENSE = 'CC BY 4.0'
_KB_LICENSE_URL = 'https://github.com/travis-burmaster/oss-security-kb/blob/main/LICENSE'
_KB_SOURCE = 'https://github.com/travis-burmaster/oss-security-kb'
_KB_MAINTAINER = 'Travis Burmaster'


def _page_name(ecosystem: str, name: str) -> str:
    """Resolve a package name to a KB page-name (without directory or extension)."""
    alias = ALIASES.get((ecosystem, name))
    if alias is not None:
        return alias
    if ecosystem == 'npm' and name.startswith('@') and '/' in name:
        scope, rest = name[1:].split('/', 1)
        return f'{scope}__{rest}'
    return name


def _match(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _table_section(text: str, heading: str) -> str:
    """Return the text between `## {heading}` and the next `## ` heading."""
    heading_re = re.compile(rf'^##\s+{re.escape(heading)}\s*$', re.MULTILINE)
    match = heading_re.search(text)
    if not match:
        return ''
    start = match.end()
    rest = text[start:]
    next_heading = re.search(r'^##\s+', rest, re.MULTILINE)
    return rest[:next_heading.start()] if next_heading else rest


def _table_rows(section: str) -> list[list[str]]:
    """Parse a Markdown table's data rows (header and separator dropped)."""
    rows: list[list[str]] = []
    for line in section.splitlines():
        line = line.strip()
        if not (line.startswith('|') and line.endswith('|')):
            continue
        cells = [cell.strip() for cell in line[1:-1].split('|')]
        if all(_TABLE_SEPARATOR_RE.match(cell) for cell in cells):
            continue  # separator row, e.g. |------|------|
        rows.append(cells)
    return rows[1:] if rows else []  # drop the header row


# A source-link cell is a short Markdown link like "[curl advisory](https://...)"
# or a bare URL; nothing legitimate needs more than this. Bounding the
# length before scanning (and using plain substring search rather than a
# regex over the whole cell) avoids quadratic blowup on a hostile cell
# packed with bracket characters -- untrusted KB Markdown must stay cheap
# to parse regardless of what a page author (or attacker) puts in a cell.
_MAX_LINK_CELL_LEN = 500


def _extract_link(cell: str) -> str | None:
    cell = cell[:_MAX_LINK_CELL_LEN]
    open_paren = cell.find('](')
    if open_paren != -1:
        close_paren = cell.find(')', open_paren + 2)
        if close_paren != -1:
            url = cell[open_paren + 2:close_paren].strip()
            return url or None
    if cell.startswith('http://') or cell.startswith('https://'):
        return cell
    return None


def _parse_audits(text: str) -> list[dict[str, object]]:
    audits: list[dict[str, object]] = []
    for cells in _table_rows(_table_section(text, 'Audit History')):
        if len(cells) < 6:
            continue  # not a well-formed audit row; skip rather than guess
        date, auditor, scope, _methodology, findings, source = cells[:6]
        if not _DATE_CELL_RE.match(date):
            continue  # placeholder row (e.g. "No audits on record"), not a date
        audits.append({
            'date': date,
            'auditor': auditor,
            'scope': scope,
            'findings': findings,
            'source': _extract_link(source),
        })
    return audits


def _parse_advisories(text: str) -> list[dict[str, object]]:
    advisories: list[dict[str, object]] = []
    for cells in _table_rows(_table_section(text, 'Known Vulnerabilities')):
        if len(cells) < 5:
            continue
        identifier, severity, _description, fixed_in, source = cells[:5]
        if not _ADVISORY_ID_RE.match(identifier):
            continue  # placeholder row (e.g. "(none on record)"), not an id
        advisories.append({
            'id': identifier,
            'severity': severity,
            'fixed_in': fixed_in,
            'source': _extract_link(source),
        })
    return advisories


def _read_page(path: Path) -> tuple[bytes | None, str | None]:
    """Read at most _MAX_PAGE_BYTES + 1 bytes; report why nothing came back."""
    try:
        with open(path, 'rb') as handle:
            data = handle.read(_MAX_PAGE_BYTES + 1)
    except OSError as exc:
        return None, f'could not read KB page: {exc}'
    if len(data) > _MAX_PAGE_BYTES:
        return None, f'KB page exceeds the {_MAX_PAGE_BYTES}-byte limit'
    return data, None


def read_kb(root: Path, package: Package) -> dict[str, object]:
    """Return local KB context for `package`, or a status explaining why not.

    Never executes anything found in the page, never follows links, and
    never lets a page name or symlink resolve outside `root`.
    """
    root = Path(root)
    ecosystem_dir = _ECOSYSTEM_PAGES.get(package.ecosystem)
    if ecosystem_dir is None:
        return {
            'status': 'unknown',
            'reason': f'unsupported ecosystem for KB lookup: {package.ecosystem}',
        }

    page_name = _page_name(package.ecosystem, package.name)
    if not _PAGE_NAME_RE.match(page_name):
        return {
            'status': 'malformed',
            'reason': f'invalid KB page name derived from package name: {page_name!r}',
        }

    relative = f'{ecosystem_dir}/{page_name}.md'
    root_resolved = root.resolve()
    candidate = root / ecosystem_dir / f'{page_name}.md'
    resolved = candidate.resolve()

    if not resolved.is_relative_to(root_resolved):
        return {
            'status': 'malformed',
            'reason': 'resolved KB page path escapes the KB root',
        }

    if not resolved.is_file():
        return {'status': 'unknown', 'reason': f'no KB page at {relative}'}

    data, error = _read_page(resolved)
    if data is None:
        return {'status': 'malformed', 'reason': error}

    text = data.decode('utf-8', errors='replace')
    kb_status = _match(_STATUS_RE, text)
    if kb_status is None:
        return {
            'status': 'malformed',
            'reason': 'KB page is missing the required "Current Status" field',
        }

    heading_match = _HEADING_RE.search(text)
    title = heading_match.group(1).strip() if heading_match else None
    repository = _match(_REPOSITORY_RE, text)
    last_updated = _match(_LAST_UPDATED_RE, text)

    snapshot = kb_snapshot(root)
    ref = snapshot.get('commit') or 'main'
    source_url = f'{_KB_SOURCE_REPO}/blob/{ref}/{relative}'

    return {
        'status': 'found',
        'page': relative,
        'title': title,
        'kb_status': kb_status,
        'repository': repository,
        'last_updated': last_updated,
        'audits': _parse_audits(text),
        'advisories': _parse_advisories(text),
        'source_url': source_url,
    }


def _read_bounded(path: Path, max_bytes: int) -> bytes | None:
    """Read at most max_bytes + 1 bytes; None if unreadable or too large."""
    try:
        with open(path, 'rb') as handle:
            data = handle.read(max_bytes + 1)
    except OSError:
        return None
    if len(data) > max_bytes:
        return None
    return data


def _resolve_head(root: Path) -> str | None:
    git_dir = root / '.git'
    head_bytes = _read_bounded(git_dir / 'HEAD', _MAX_HEAD_BYTES)
    if head_bytes is None:
        return None
    content = head_bytes.decode('utf-8', errors='replace').strip()

    if _COMMIT_RE.match(content):
        return content

    if not content.startswith('ref:'):
        return None  # garbage HEAD content

    ref = content[len('ref:'):].strip()
    if not _REF_RE.match(ref):
        return None  # refuse to build a path from an unexpected ref shape

    git_dir_resolved = git_dir.resolve()
    ref_path_resolved = (git_dir / ref).resolve()
    if not ref_path_resolved.is_relative_to(git_dir_resolved):
        return None  # ref tries to escape .git/

    ref_bytes = _read_bounded(git_dir / ref, _MAX_REF_BYTES)
    if ref_bytes is not None:
        ref_content = ref_bytes.decode('utf-8', errors='replace').strip()
        if _COMMIT_RE.match(ref_content):
            return ref_content

    packed = _read_bounded(git_dir / 'packed-refs', _MAX_PACKED_REFS_BYTES)
    if packed is None:
        return None
    text = packed.decode('utf-8', errors='replace')
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('^'):
            continue
        parts = line.split(' ', 1)
        if len(parts) != 2:
            continue
        commit_id, ref_name = parts
        if ref_name.strip() == ref and _COMMIT_RE.match(commit_id):
            return commit_id
    return None


def kb_snapshot(root: Path) -> dict[str, object]:
    """Identify the KB checkout at `root` without ever running `git`.

    Reads `.git/HEAD` (and, if it is a symbolic ref, the referenced loose
    ref or `packed-refs`) directly as plain files, each bounded in size.
    `dirty` is always None: working-tree cleanliness is not determined,
    because doing so would require running `git status`, which a
    KB-local `.git/config` could hijack via `core.fsmonitor` or
    `core.hooksPath`.
    """
    root = Path(root)
    return {'commit': _resolve_head(root), 'dirty': None, 'root': str(root)}


def kb_metadata(kb_root: Path | None) -> dict[str, object]:
    """Build the once-per-report metadata['kb'] entry, in a single shape.

    Shared by every adapter that reports package-level KB context:
    'unavailable' when no --kb was supplied at all; 'unreadable' when a
    path was supplied but does not exist or is not a directory; else
    'available', carrying the KB snapshot identity plus attribution
    (license, source, maintainer) so it is preserved wherever this
    report ends up, per the KB's attribution requirements.
    """
    if kb_root is None:
        return {'status': 'unavailable', 'reason': 'no --kb path supplied'}
    kb_root = Path(kb_root)
    if not kb_root.is_dir():
        return {
            'status': 'unreadable',
            'root': str(kb_root),
            'reason': f'--kb path does not exist or is not a directory: {kb_root}',
        }
    snapshot = kb_snapshot(kb_root)
    return {
        'status': 'available',
        'root': snapshot.get('root'),
        'commit': snapshot.get('commit'),
        'dirty': snapshot.get('dirty'),
        'license': _KB_LICENSE,
        'license_url': _KB_LICENSE_URL,
        'source': _KB_SOURCE,
        'maintainer': _KB_MAINTAINER,
    }


def kb_unreadable_reason(metadata: dict[str, object]) -> str | None:
    """Return why a KB root is unreadable, or None if `metadata` says it's fine.

    `metadata` is the return value of `kb_metadata`. Shared by every
    adapter that needs to react to an unreadable --kb path the same way:
    skip per-package KB lookups entirely (no `read_kb` call, and no
    accidental 'unknown'-from-a-never-readable-root verdict), record the
    reason in `errors`, and downgrade completion to 'partial' rather than
    reporting a clean or silently degraded result.
    """
    return metadata.get('reason') if metadata.get('status') == 'unreadable' else None
