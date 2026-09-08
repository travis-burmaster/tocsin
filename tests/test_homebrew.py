import json
from pathlib import Path

import pytest

from tocsin.models import CommandResult
from tocsin.platforms import macos
from tocsin.platforms.macos import inventory_brew, parse_brew

FIXTURES = Path(__file__).parent / 'fixtures'
REAL_BREW_JSON = (FIXTURES / 'homebrew' / 'brew-info-installed.json').read_text()
KB_FIXTURES = FIXTURES / 'kb'


# --- parse_brew: the real trimmed fixture -----------------------------------

def test_parse_real_fixture_covers_multi_version_revision_and_tap():
    packages = parse_brew(REAL_BREW_JSON)

    by_name = {}
    for pkg in packages:
        by_name.setdefault(pkg.name, []).append(pkg)

    # git: single installed version carrying a "_1" revision suffix.
    (git,) = by_name['git']
    assert git.ecosystem == 'homebrew'
    assert git.version == '2.53.0'
    assert git.provenance['revision'] == '1'
    assert git.provenance['tap'] == 'homebrew/core'
    assert git.provenance['kind'] == 'formula'
    assert git.provenance['installed_on_request'] == 'true'

    # openssl@3: versioned formula name, preserved verbatim.
    (openssl,) = by_name['openssl@3']
    assert openssl.name == 'openssl@3'
    assert openssl.version == '3.6.3'

    # ca-certificates: two installed versions -> two Packages.
    assert len(by_name['ca-certificates']) == 2
    versions = {p.version for p in by_name['ca-certificates']}
    assert versions == {'2026-05-14', '2026-07-16'}

    # terraform: third-party tap, never merged into a core name.
    (terraform,) = by_name['terraform']
    assert terraform.provenance['tap'] == 'hashicorp/tap'
    assert terraform.provenance['full_name'] == 'hashicorp/tap/terraform'

    # drawio: a cask, kept separate and unassessed.
    cask_names = {p.name for p in packages if p.ecosystem == 'homebrew-cask'}
    assert cask_names == {'drawio'}
    (drawio,) = [p for p in packages if p.name == 'drawio']
    assert drawio.ecosystem == 'homebrew-cask'
    assert drawio.provenance['kind'] == 'cask'
    assert drawio.version == '30.3.14'  # the installed version, not the latest available


# --- parse_brew: focused, hand-written edge cases ---------------------------

def _brew_payload(formulae=None, casks=None) -> str:
    return json.dumps({'formulae': formulae or [], 'casks': casks or []})


def test_revision_suffix_is_split_from_version():
    payload = _brew_payload(formulae=[{
        'name': 'thing',
        'full_name': 'thing',
        'tap': 'homebrew/core',
        'revision': 0,
        'installed': [{'version': '8.0.0_1', 'installed_on_request': True}],
    }])

    (pkg,) = parse_brew(payload)

    assert pkg.version == '8.0.0'
    assert pkg.provenance['revision'] == '1'


def test_formula_level_revision_used_when_no_suffix():
    payload = _brew_payload(formulae=[{
        'name': 'thing',
        'full_name': 'thing',
        'tap': 'homebrew/core',
        'revision': 3,
        'installed': [{'version': '1.2.3'}],
    }])

    (pkg,) = parse_brew(payload)

    assert pkg.version == '1.2.3'
    assert pkg.provenance['revision'] == '3'


def test_multiple_installed_versions_yield_multiple_packages():
    payload = _brew_payload(formulae=[{
        'name': 'multi',
        'full_name': 'multi',
        'tap': 'homebrew/core',
        'installed': [{'version': '1.0.0'}, {'version': '2.0.0'}],
    }])

    packages = parse_brew(payload)

    assert [p.version for p in packages] == ['1.0.0', '2.0.0']


def test_installed_flags_preserved_only_when_present():
    payload = _brew_payload(formulae=[
        {
            'name': 'with-flags',
            'full_name': 'with-flags',
            'tap': 'homebrew/core',
            'installed': [{
                'version': '1.0.0',
                'installed_as_dependency': True,
                'installed_on_request': False,
            }],
        },
        {
            'name': 'without-flags',
            'full_name': 'without-flags',
            'tap': 'homebrew/core',
            'installed': [{'version': '1.0.0'}],
        },
    ])

    with_flags, without_flags = parse_brew(payload)

    assert with_flags.provenance['installed_as_dependency'] == 'true'
    assert with_flags.provenance['installed_on_request'] == 'false'
    assert 'installed_as_dependency' not in without_flags.provenance
    assert 'installed_on_request' not in without_flags.provenance


def test_architecture_preserved_when_provided():
    payload = _brew_payload(formulae=[{
        'name': 'arch-aware',
        'full_name': 'arch-aware',
        'tap': 'homebrew/core',
        'installed': [{'version': '1.0.0', 'architecture': 'arm64'}],
    }])

    (pkg,) = parse_brew(payload)

    assert pkg.provenance['architecture'] == 'arm64'


def test_third_party_tap_is_not_merged_into_core_name():
    payload = _brew_payload(formulae=[{
        'name': 'curl',  # deliberately shadows the core formula name
        'full_name': 'someone/tap/curl',
        'tap': 'someone/tap',
        'installed': [{'version': '9.9.9'}],
    }])

    (pkg,) = parse_brew(payload)

    assert pkg.provenance['tap'] == 'someone/tap'
    assert pkg.provenance['full_name'] == 'someone/tap/curl'


def test_cask_without_installed_version_is_skipped():
    payload = _brew_payload(casks=[{
        'token': 'not-really-installed',
        'full_token': 'not-really-installed',
        'tap': 'homebrew/cask',
        'installed': None,
    }])

    assert parse_brew(payload) == []


def test_malformed_brew_json_raises_decode_error():
    with pytest.raises(json.JSONDecodeError):
        parse_brew('not json at all')


# --- inventory_brew: Homebrew missing ---------------------------------------

def test_inventory_unavailable_when_brew_not_on_path(monkeypatch):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: None)

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called when brew is absent')

    result = inventory_brew(kb_root=None, runner=_forbidden)

    assert result.name == 'brew'
    assert result.completion == 'unavailable'
    assert result.findings == ()
    assert result.metadata['coverage'] == {'assessed': 0, 'unassessed': 0}


def test_inventory_unavailable_when_runner_reports_missing(monkeypatch):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(None, '', '', 'missing')

    result = inventory_brew(kb_root=None, runner=fake_runner)

    assert result.completion == 'unavailable'


# --- inventory_brew: runner failure mapping ---------------------------------

@pytest.mark.parametrize('failure', ['timeout', 'output-limit', 'cancelled'])
def test_inventory_partial_on_bounded_runner_failures(monkeypatch, failure):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(None, '', '', failure)

    result = inventory_brew(kb_root=None, runner=fake_runner)

    assert result.completion == 'partial'
    assert result.errors


def test_inventory_error_on_permission_failure(monkeypatch):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(None, '', '', 'permission')

    result = inventory_brew(kb_root=None, runner=fake_runner)

    assert result.completion == 'error'


def test_inventory_error_on_nonzero_returncode(monkeypatch):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(1, '', 'boom', None)

    result = inventory_brew(kb_root=None, runner=fake_runner)

    assert result.completion == 'error'
    assert 'boom' in result.errors[0]


def test_inventory_error_on_unparseable_json(monkeypatch):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, 'not json', '', None)

    result = inventory_brew(kb_root=None, runner=fake_runner)

    assert result.completion == 'error'


# --- inventory_brew: success path -------------------------------------------

def test_inventory_success_reports_complete_with_unassessed_findings(monkeypatch):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')
    payload = _brew_payload(formulae=[{
        'name': 'thing',
        'full_name': 'thing',
        'tap': 'homebrew/core',
        'installed': [{'version': '1.0.0'}],
    }])

    captured = {}

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        captured['argv'] = argv
        captured['timeout'] = timeout
        captured['max_bytes'] = max_bytes
        captured['extra_env'] = extra_env
        return CommandResult(0, payload, '', None)

    result = inventory_brew(kb_root=None, runner=fake_runner)

    assert result.completion == 'complete'
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.status == 'unassessed'
    assert finding.subject == 'thing 1.0.0'
    assert finding.action == 'no reviewed advisory adapter for this formula'
    assert finding.evidence == ()
    assert finding.observed_at.endswith('Z')

    assert result.metadata['coverage'] == {'assessed': 0, 'unassessed': 1}
    assert result.metadata['kb'] == {'status': 'unavailable', 'reason': 'no --kb path supplied'}
    assert result.metadata['packages'][0]['kb']['status'] == 'unavailable'
    assert result.metadata['command'] == captured['argv']

    assert captured['argv'][0] == '/opt/homebrew/bin/brew'
    assert captured['argv'][1:] == ['info', '--json=v2', '--installed']
    assert captured['timeout'] == 120
    assert captured['max_bytes'] == 16 * 1024 * 1024
    assert captured['extra_env'] == {'HOMEBREW_NO_AUTO_UPDATE': '1'}


def test_inventory_cask_action_differs_from_formula(monkeypatch):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')
    payload = _brew_payload(casks=[{
        'token': 'some-app',
        'full_token': 'some-app',
        'tap': 'homebrew/cask',
        'installed': '1.0.0',
    }])

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, payload, '', None)

    result = inventory_brew(kb_root=None, runner=fake_runner)

    assert result.completion == 'complete'
    assert result.findings[0].action == 'casks are outside initial vulnerability coverage'


def test_inventory_with_real_kb_attaches_found_context_and_evidence(monkeypatch):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')
    payload = _brew_payload(formulae=[{
        'name': 'curl',
        'full_name': 'curl',
        'tap': 'homebrew/core',
        'installed': [{'version': '8.9.1'}],
    }])

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, payload, '', None)

    result = inventory_brew(kb_root=KB_FIXTURES, runner=fake_runner)

    finding = result.findings[0]
    assert finding.evidence != ()
    assert finding.evidence[0].endswith('/wiki/homebrew/curl.md')
    package_entry = result.metadata['packages'][0]
    assert package_entry['kb']['status'] == 'found'
    assert package_entry['kb']['kb_status'] == 'advisory-mapped'
    assert result.metadata['kb']['root'] == str(KB_FIXTURES)


def test_inventory_third_party_tap_kb_context_is_unavailable_with_reason(monkeypatch):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')
    payload = _brew_payload(formulae=[{
        'name': 'curl',  # shadows core name, but from a different tap
        'full_name': 'someone/tap/curl',
        'tap': 'someone/tap',
        'installed': [{'version': '9.9.9'}],
    }])

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, payload, '', None)

    result = inventory_brew(kb_root=KB_FIXTURES, runner=fake_runner)

    kb_context = result.metadata['packages'][0]['kb']
    assert kb_context['status'] == 'unavailable'
    assert 'someone/tap' in kb_context['reason']
    assert result.findings[0].evidence == ()


def test_inventory_unassessed_packages_do_not_block_completion(monkeypatch):
    monkeypatch.setattr(macos.shutil, 'which', lambda name: '/opt/homebrew/bin/brew')

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, REAL_BREW_JSON, '', None)

    result = inventory_brew(kb_root=None, runner=fake_runner)

    assert result.completion == 'complete'
    assert all(f.status == 'unassessed' for f in result.findings)
    assert result.metadata['coverage']['assessed'] == 0
    assert result.metadata['coverage']['unassessed'] == len(result.findings)
