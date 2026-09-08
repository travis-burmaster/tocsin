import os
import subprocess
from pathlib import Path

import pytest

from tocsin import kb
from tocsin.kb import kb_snapshot, read_kb
from tocsin.models import Package

FIXTURES = Path(__file__).parent / 'fixtures' / 'kb'


def test_missing_kb_page_is_unknown(tmp_path):
    package = Package('homebrew', 'absent', '1.0', {})
    context = read_kb(tmp_path, package)
    assert context['status'] == 'unknown'


# --- real curl/openssl@3 fixture pages -------------------------------------

def test_real_curl_page_is_found_with_advisories():
    package = Package('homebrew', 'curl', '8.9.1', {})

    context = read_kb(FIXTURES, package)

    assert context['status'] == 'found'
    assert context['page'] == 'wiki/homebrew/curl.md'
    assert context['kb_status'] == 'advisory-mapped'
    assert context['last_updated'] == '2026-07-11'
    advisory_ids = {a['id'] for a in context['advisories']}
    assert 'CVE-2023-38545' in advisory_ids
    assert 'CVE-2025-0167' in advisory_ids
    high = next(a for a in context['advisories'] if a['id'] == 'CVE-2023-38545')
    assert high['severity'] == 'High'
    assert high['source'] == 'https://curl.se/docs/CVE-2023-38545.html'
    assert context['source_url'].startswith(
        'https://github.com/travis-burmaster/oss-security-kb/blob/'
    )
    assert context['source_url'].endswith('/wiki/homebrew/curl.md')
    # curl.md's Audit History table has no data rows at all.
    assert context['audits'] == []


def test_real_openssl_page_is_baseline_stub_with_placeholders_filtered():
    package = Package('homebrew', 'openssl@3', '3.6.2', {})

    context = read_kb(FIXTURES, package)

    assert context['status'] == 'found'
    assert context['page'] == 'wiki/homebrew/openssl@3.md'
    assert context['kb_status'] == 'baseline stub'
    assert context['last_updated'] == '2026-04-27'
    # Both tables only contain placeholder rows ("No public proactive
    # audits...", "Review pending") which must not be reported as real
    # audits or advisories.
    assert context['audits'] == []
    assert context['advisories'] == []


def test_versioned_formula_name_maps_directly_to_page():
    # 'openssl@3' is used as-is as the page-name; no alias needed.
    package = Package('homebrew', 'openssl@3', '3.6.2', {})

    context = read_kb(FIXTURES, package)

    assert context['page'] == 'wiki/homebrew/openssl@3.md'


# --- npm scoped names and aliasing ------------------------------------------

def test_scoped_npm_name_is_derived_as_scope_double_underscore_name():
    package = Package('npm', '@foo/bar', '1.0.0', {})

    context = read_kb(FIXTURES, package)

    assert context['status'] == 'found'
    assert context['page'] == 'wiki/npm/foo__bar.md'


def test_explicit_alias_overrides_derived_page_name(monkeypatch):
    monkeypatch.setitem(kb.ALIASES, ('npm', '@acme/widget'), 'acme-widget-fixture')
    package = Package('npm', '@acme/widget', '2.0.0', {})

    context = read_kb(FIXTURES, package)

    assert context['status'] == 'found'
    assert context['page'] == 'wiki/npm/acme-widget-fixture.md'


# --- ecosystem gating --------------------------------------------------------

def test_unknown_ecosystem_reports_unknown_with_reason():
    package = Package('cobol-copybooks', 'thing', '1.0', {})

    context = read_kb(FIXTURES, package)

    assert context['status'] == 'unknown'
    assert 'cobol-copybooks' in context['reason']


# --- malformed / stub pages --------------------------------------------------

def test_malformed_page_without_status_line_is_malformed():
    package = Package('homebrew', 'malformed', '1.0', {})

    context = read_kb(FIXTURES, package)

    assert context['status'] == 'malformed'
    assert 'reason' in context


def test_stub_page_status_is_extracted():
    package = Package('homebrew', 'stub-formula', '0.1', {})

    context = read_kb(FIXTURES, package)

    assert context['status'] == 'found'
    assert context['kb_status'] == 'baseline stub'
    assert context['advisories'] == []
    assert context['audits'] == []


# --- size and path-safety limits --------------------------------------------

def test_oversized_page_is_malformed(tmp_path):
    page_dir = tmp_path / 'wiki' / 'homebrew'
    page_dir.mkdir(parents=True)
    big_page = page_dir / 'big.md'
    big_page.write_bytes(b'# big\n\n**Current Status:** baseline stub\n' + b'x' * (1024 * 1024 + 10))
    package = Package('homebrew', 'big', '1.0', {})

    context = read_kb(tmp_path, package)

    assert context['status'] == 'malformed'


def test_symlink_escape_is_rejected(tmp_path):
    kb_root = tmp_path / 'kb'
    outside = tmp_path / 'outside'
    (kb_root / 'wiki' / 'homebrew').mkdir(parents=True)
    outside.mkdir()
    secret = outside / 'secret.md'
    secret.write_text('# secret\n\n**Current Status:** baseline stub\n')
    escape_link = kb_root / 'wiki' / 'homebrew' / 'escape.md'
    escape_link.symlink_to(secret)
    package = Package('homebrew', 'escape', '1.0', {})

    context = read_kb(kb_root, package)

    assert context['status'] == 'malformed'
    assert 'escapes' in context['reason']


def test_invalid_page_name_is_rejected(tmp_path):
    package = Package('homebrew', '../../etc/passwd', '1.0', {})

    context = read_kb(tmp_path, package)

    assert context['status'] == 'malformed'


# --- kb_snapshot: never runs git ---------------------------------------------

def _write_poisoned_config(git_dir: Path) -> None:
    """A .git/config that would run arbitrary programs if `git` ran here."""
    (git_dir / 'config').write_text(
        '[core]\n\tfsmonitor = /bin/false\n\thooksPath = /nonexistent\n'
    )


def test_snapshot_reads_direct_head(tmp_path):
    git_dir = tmp_path / '.git'
    git_dir.mkdir()
    _write_poisoned_config(git_dir)
    commit = 'a' * 40
    (git_dir / 'HEAD').write_text(commit + '\n')

    snapshot = kb_snapshot(tmp_path)

    assert snapshot['commit'] == commit
    assert snapshot['dirty'] is None
    assert snapshot['root'] == str(tmp_path)


def test_snapshot_resolves_symbolic_head_via_refs_heads(tmp_path):
    git_dir = tmp_path / '.git'
    (git_dir / 'refs' / 'heads').mkdir(parents=True)
    _write_poisoned_config(git_dir)
    (git_dir / 'HEAD').write_text('ref: refs/heads/main\n')
    commit = 'b' * 40
    (git_dir / 'refs' / 'heads' / 'main').write_text(commit + '\n')

    snapshot = kb_snapshot(tmp_path)

    assert snapshot['commit'] == commit


def test_snapshot_falls_back_to_packed_refs(tmp_path):
    git_dir = tmp_path / '.git'
    git_dir.mkdir()
    _write_poisoned_config(git_dir)
    (git_dir / 'HEAD').write_text('ref: refs/heads/main\n')
    commit = 'c' * 40
    (git_dir / 'packed-refs').write_text(
        f'# pack-refs with: peeled fully-peeled sorted\n{commit} refs/heads/main\n'
    )

    snapshot = kb_snapshot(tmp_path)

    assert snapshot['commit'] == commit


def test_snapshot_garbage_head_is_none(tmp_path):
    git_dir = tmp_path / '.git'
    git_dir.mkdir()
    _write_poisoned_config(git_dir)
    (git_dir / 'HEAD').write_text('not a ref or a commit\n')

    snapshot = kb_snapshot(tmp_path)

    assert snapshot['commit'] is None


def test_snapshot_missing_git_dir_is_none(tmp_path):
    snapshot = kb_snapshot(tmp_path)

    assert snapshot['commit'] is None
    assert snapshot['dirty'] is None


def test_snapshot_never_spawns_a_process(tmp_path, monkeypatch):
    git_dir = tmp_path / '.git'
    (git_dir / 'refs' / 'heads').mkdir(parents=True)
    _write_poisoned_config(git_dir)
    (git_dir / 'HEAD').write_text('ref: refs/heads/main\n')
    (git_dir / 'refs' / 'heads' / 'main').write_text('d' * 40 + '\n')

    def _forbidden(*args, **kwargs):
        raise AssertionError('kb_snapshot must never spawn a process')

    monkeypatch.setattr(subprocess, 'Popen', _forbidden)
    monkeypatch.setattr(os, 'popen', _forbidden)

    snapshot = kb_snapshot(tmp_path)

    assert snapshot['commit'] == 'd' * 40
