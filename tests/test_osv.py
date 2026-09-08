import json
import os
from pathlib import Path

import pytest

from tocsin.adapters import osv as osv_module
from tocsin.adapters.osv import normalize_osv, scan_project
from tocsin.models import CommandResult
from tocsin.report import exit_code
from tocsin.runner import run_command

FIXTURES = Path(__file__).parent / 'fixtures' / 'osv'
FINDINGS_JSON = (FIXTURES / 'findings.json').read_text()
EMPTY_JSON = (FIXTURES / 'empty.json').read_text()
NULL_RESULTS_JSON = (FIXTURES / 'null_results.json').read_text()
MALFORMED_JSON = (FIXTURES / 'malformed.json').read_text()
WRONG_SCHEMA_JSON = (FIXTURES / 'wrong_schema.json').read_text()
VERSION_OUTPUT = (FIXTURES / 'version.txt').read_text()
STDERR_NO_DB_PYPI = (FIXTURES / 'stderr_no_offline_db_pypi.txt').read_text()

OSV_PATH = '/opt/homebrew/bin/osv-scanner'


def _fake_which(monkeypatch, path=OSV_PATH):
    monkeypatch.setattr(osv_module.shutil, 'which', lambda name: path)


def _version_call(argv, *, timeout, max_bytes, extra_env=None):
    assert argv == [OSV_PATH, '--version']
    return CommandResult(0, VERSION_OUTPUT, '', None)


def _runner(version=_version_call, scan=None):
    """Build a fake runner distinguishing the version call from the scan
    call by argv shape: the version call is exactly [osv_path, '--version'];
    everything else is the scan invocation.
    """
    def fake(argv, *, timeout, max_bytes, extra_env=None):
        if argv == [OSV_PATH, '--version']:
            return version(argv, timeout=timeout, max_bytes=max_bytes, extra_env=extra_env)
        assert scan is not None, 'runner must not be called for the scan when database/offline gating should stop first'
        return scan(argv, timeout=timeout, max_bytes=max_bytes, extra_env=extra_env)
    return fake


# --- offline default without a database (the brief's named test) -----------

def test_offline_without_database_is_unavailable(tmp_path):
    result = scan_project(tmp_path, online=False, database=None)
    assert result.completion == 'unavailable'


def test_offline_without_database_never_calls_runner(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called when offline and no database is supplied')

    result = scan_project(tmp_path, online=False, database=None, runner=_forbidden)

    assert result.completion == 'unavailable'
    assert 'osv-database' in result.errors[0] or '--online' in result.errors[0]
    assert 'command' not in result.metadata


def test_offline_with_missing_database_path_is_unavailable_and_names_path(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    missing_db = tmp_path / 'does-not-exist'

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called when the database path is missing')

    result = scan_project(tmp_path, online=False, database=missing_db, runner=_forbidden)

    assert result.completion == 'unavailable'
    assert str(missing_db) in result.errors[0]
    assert 'command' not in result.metadata


def test_offline_with_database_path_that_is_a_file_is_unavailable(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    db_file = tmp_path / 'db-is-a-file'
    db_file.write_text('oops')

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called when the database path is not a directory')

    result = scan_project(tmp_path, online=False, database=db_file, runner=_forbidden)

    assert result.completion == 'unavailable'
    assert str(db_file) in result.errors[0]


# --- engine discovery --------------------------------------------------

def test_missing_engine_is_unavailable_and_runner_not_called(monkeypatch, tmp_path):
    monkeypatch.setattr(osv_module.shutil, 'which', lambda name: None)

    def _forbidden(*args, **kwargs):
        raise AssertionError('runner must not be called when osv-scanner is absent')

    result = scan_project(tmp_path, online=True, database=None, runner=_forbidden)

    assert result.completion == 'unavailable'
    assert 'osv-scanner not found on PATH' in result.errors[0]


# --- version guard -------------------------------------------------------

@pytest.mark.parametrize('version_text', [
    'osv-scanner version: 2.4.0\n',
    'osv-scanner version: 3.0.0\n',
    'garbage output with no version line\n',
])
def test_version_rejection(monkeypatch, tmp_path, version_text):
    _fake_which(monkeypatch)

    def fake(argv, *, timeout, max_bytes, extra_env=None):
        assert argv == [OSV_PATH, '--version']
        return CommandResult(0, version_text, '', None)

    result = scan_project(tmp_path, online=True, database=None, runner=fake)

    assert result.completion == 'unavailable'
    assert 'tocsin is tested against' in result.errors[0] or 'tested against' in result.errors[0]


def test_version_guard_timeout_is_partial(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def fake(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(None, '', '', 'timeout')

    result = scan_project(tmp_path, online=True, database=None, runner=fake)

    assert result.completion == 'partial'


def test_version_guard_permission_is_error(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def fake(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(None, '', '', 'permission')

    result = scan_project(tmp_path, online=True, database=None, runner=fake)

    assert result.completion == 'error'


# --- argv / extra_env construction -----------------------------------------

def test_offline_argv_and_extra_env(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    database = tmp_path / 'db'
    database.mkdir()
    captured = {}

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        captured['argv'] = argv
        captured['timeout'] = timeout
        captured['max_bytes'] = max_bytes
        captured['extra_env'] = extra_env
        return CommandResult(0, EMPTY_JSON, '', None)

    result = scan_project(tmp_path, online=False, database=database, runner=_runner(scan=scan))

    assert result.completion == 'complete'
    resolved = str(tmp_path.resolve())
    assert captured['argv'] == [
        OSV_PATH, 'scan', 'source', '--recursive', '--offline',
        '--no-resolve', '--format', 'json', resolved,
    ]
    assert captured['extra_env'] == {'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY': str(database)}
    assert captured['timeout'] == 600
    assert captured['max_bytes'] == 64 * 1024 * 1024


def test_online_argv_has_no_offline_flag_or_extra_env(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    captured = {}

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        captured['argv'] = argv
        captured['extra_env'] = extra_env
        return CommandResult(0, EMPTY_JSON, '', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'complete'
    resolved = str(tmp_path.resolve())
    assert captured['argv'] == [
        OSV_PATH, 'scan', 'source', '--recursive',
        '--no-resolve', '--format', 'json', resolved,
    ]
    assert '--offline' not in captured['argv']
    assert captured['extra_env'] is None


# --- normalize_osv: malformed / wrong schema --------------------------------

def test_normalize_malformed_json_is_error():
    result = normalize_osv(MALFORMED_JSON)
    assert result.completion == 'error'


def test_normalize_wrong_schema_is_error():
    result = normalize_osv(WRONG_SCHEMA_JSON)
    assert result.completion == 'error'
    assert 'unsupported osv-scanner output schema' in result.errors[0]


def test_normalize_null_results_is_complete_with_zero_manifests():
    result = normalize_osv(NULL_RESULTS_JSON)
    assert result.completion == 'complete'
    assert result.findings == ()
    assert result.metadata['manifests'] == 0


# --- normalize_osv: real findings fixture -----------------------------------

def test_normalize_real_findings_fixture():
    result = normalize_osv(FINDINGS_JSON)

    assert result.completion == 'complete'
    assert len(result.findings) == 4
    assert result.metadata['packages'] == 2
    assert result.metadata['packages_with_findings'] == 2
    assert result.metadata['manifests'] == 1

    requests_finding = next(f for f in result.findings if f.subject.startswith('requests'))
    assert requests_finding.subject == 'requests 2.19.0 (PyPI)'
    assert requests_finding.severity in {'7.5', '6.1'}
    assert any('manifest: ' in e for e in requests_finding.evidence)
    assert any(e.startswith('CVE-') for e in requests_finding.evidence)
    assert 'upgrade to' in requests_finding.action


# --- scan_project: rc handling ----------------------------------------------

def test_scan_rc0_findings_fixture_is_complete(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, FINDINGS_JSON, '', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'complete'
    assert len(result.findings) == 4
    assert result.metadata['engine'] == {'name': 'osv-scanner', 'version': '2.5.1'}
    assert result.metadata['mode'] == 'online'


def test_scan_rc1_findings_fixture_is_complete(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(1, FINDINGS_JSON, '', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'complete'
    assert len(result.findings) == 4


def test_scan_empty_success_is_complete_with_one_unassessed_finding(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, EMPTY_JSON, '', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'complete'
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.status == 'unassessed'
    assert finding.category == 'dependency'
    assert finding.subject == str(tmp_path.resolve())
    assert result.metadata['manifests'] == 0
    assert result.metadata['coverage'] == {'assessed': 0, 'unassessed': 1}


def test_scan_null_results_is_complete_with_one_unassessed_finding(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, NULL_RESULTS_JSON, '', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'complete'
    assert len(result.findings) == 1
    assert result.findings[0].status == 'unassessed'


def test_scan_rc128_no_packages_found_is_complete_with_one_unassessed_finding(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(128, '', 'No package sources found, --help for usage information.', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'complete'
    assert len(result.findings) == 1
    assert result.findings[0].status == 'unassessed'
    assert result.metadata['manifests'] == 0


def test_scan_rc127_no_offline_db_names_pypi_and_is_unavailable(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    database = tmp_path / 'db'
    database.mkdir()

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(127, EMPTY_JSON, STDERR_NO_DB_PYPI, None)

    result = scan_project(tmp_path, online=False, database=database, runner=_runner(scan=scan))

    assert result.completion == 'unavailable'
    assert 'PyPI' in result.errors[0]


def test_scan_rc127_other_error_is_error(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(127, '', 'some unrelated fatal error', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'error'


def test_scan_rc129_is_error_api_failed(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(129, '', 'api boom', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'error'
    assert result.errors == ('OSV API failed',)


def test_scan_rc130_is_error_invalid_config(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(130, '', 'bad config', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'error'
    assert result.errors == ('invalid osv-scanner config',)


def test_scan_unexpected_rc_is_error(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(2, '', 'unexpected', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'error'


def test_scan_timeout_is_partial(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(None, '', '', 'timeout')

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'partial'
    assert result.findings == ()


def test_scan_permission_failure_is_error(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(None, '', '', 'permission')

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'error'


def test_scan_malformed_json_rc0_is_error(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, MALFORMED_JSON, '', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'error'


def test_scan_wrong_schema_rc1_is_error(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(1, WRONG_SCHEMA_JSON, '', None)

    result = scan_project(tmp_path, online=True, database=None, runner=_runner(scan=scan))

    assert result.completion == 'error'


# --- KB enrichment -----------------------------------------------------

def test_kb_enrichment_attaches_source_url_for_requests(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    kb_root = tmp_path / 'kb'
    (kb_root / 'wiki' / 'python').mkdir(parents=True)
    page = kb_root / 'wiki' / 'python' / 'requests.md'
    page.write_text(
        '# requests (PyPI)\n\n'
        '**Current Status:** advisory-mapped\n\n'
        '## Audit History\n\n'
        '## Known Vulnerabilities\n\n'
        '| CVE / Issue | Severity | Description | Fixed in | Source |\n'
        '|---|---|---|---|---|\n'
    )

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, FINDINGS_JSON, '', None)

    result = scan_project(tmp_path, online=True, database=None, kb_root=kb_root, runner=_runner(scan=scan))

    assert result.completion == 'complete'
    kb_entry = result.metadata['packages_kb']['PyPI:requests:2.19.0']
    assert kb_entry['status'] == 'found'
    assert kb_entry['source_url'].endswith('/wiki/python/requests.md')

    requests_finding = next(f for f in result.findings if f.subject.startswith('requests'))
    assert any(e.endswith('/wiki/python/requests.md') for e in requests_finding.evidence)


def test_kb_root_none_reports_unavailable_per_package(monkeypatch, tmp_path):
    _fake_which(monkeypatch)

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, FINDINGS_JSON, '', None)

    result = scan_project(tmp_path, online=True, database=None, kb_root=None, runner=_runner(scan=scan))

    assert result.metadata['kb'] == {'status': 'unavailable', 'reason': 'no --kb path supplied'}
    kb_entry = result.metadata['packages_kb']['PyPI:requests:2.19.0']
    assert kb_entry == {'status': 'unavailable', 'reason': 'no --kb path supplied'}


def test_kb_unsupported_ecosystem_is_unavailable_with_reason(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    kb_root = tmp_path / 'kb'
    kb_root.mkdir()
    payload = json.dumps({
        'results': [{
            'source': {'path': '/proj/go.sum', 'type': 'lockfile'},
            'packages': [{
                'package': {'name': 'example.com/mod', 'version': '1.0.0', 'ecosystem': 'Bazaar'},
                'groups': [{'ids': ['OSV-1'], 'aliases': ['OSV-1'], 'max_severity': ''}],
                'vulnerabilities': [{
                    'id': 'OSV-1', 'aliases': [], 'affected': [], 'references': [],
                }],
            }],
        }],
        'experimental_config': {},
    })

    def scan(argv, *, timeout, max_bytes, extra_env=None):
        return CommandResult(0, payload, '', None)

    result = scan_project(tmp_path, online=True, database=None, kb_root=kb_root, runner=_runner(scan=scan))

    kb_entry = result.metadata['packages_kb']['Bazaar:example.com/mod:1.0.0']
    assert kb_entry['status'] == 'unavailable'
    assert 'Bazaar' in kb_entry['reason']
    assert result.findings[0].severity == 'unknown'
    assert result.findings[0].action == 'review advisory'


# --- optional local integration: the real osv-scanner v2.5.1 binary --------

_REAL_OSV_SCANNER = os.environ.get('TOCSIN_OSV_SCANNER')
_REAL_OSV_DB = os.environ.get('TOCSIN_OSV_DB')


@pytest.mark.skipif(
    not (_REAL_OSV_SCANNER and _REAL_OSV_DB),
    reason='set TOCSIN_OSV_SCANNER and TOCSIN_OSV_DB to run the real osv-scanner integration test',
)
def test_real_osv_scanner_offline_scan_detects_requests_cve(monkeypatch, tmp_path):
    (tmp_path / 'requirements.txt').write_text('requests==2.19.0\n')
    monkeypatch.setattr(osv_module.shutil, 'which', lambda name: _REAL_OSV_SCANNER)

    result = scan_project(
        tmp_path, online=False, database=Path(_REAL_OSV_DB), runner=run_command,
    )

    assert result.completion == 'complete'
    assert any(f.status == 'detected' for f in result.findings)
    assert exit_code([result]) == 1
