"""Regression test AND generator for docs/samples/report-sample.{txt,json}.

Builds the exact fixture-driven scan this project publishes as sample
output (`tocsin.cli.main` with an injected fake `Runner`, fixture JSON
payloads for Homebrew/OSV-Scanner/ClamAV, and a fixed `generated_at` so
the output is byte-for-byte reproducible), renders both formats, and
compares them to the checked-in `docs/samples/report-sample.txt` and
`report-sample.json`. A renderer change (`tocsin.report.render_text`/
`render_json`) that isn't reflected in the published samples fails this
test loudly, rather than silently drifting.

This replaces the one-off, not-checked-in scratch script that originally
produced these samples (see docs/samples/README.md's history). To
regenerate the published samples after a deliberate, intentional change
to the renderer or to this test's fixture inputs, run this file directly:

    .venv/bin/python tests/test_samples.py

which overwrites docs/samples/report-sample.{txt,json} with this test's
own freshly rendered output, then re-run the test to confirm it passes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import tocsin.cli as cli_module
from tocsin.models import CommandResult
from tocsin.platforms import macos

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "docs" / "samples"
KB_ROOT = REPO_ROOT / "tests" / "fixtures" / "kb"
CLAMAV_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "clamav"
CLAMAV_HELP_TEXT = (CLAMAV_FIXTURES / "help.txt").read_text()
CLAMAV_VERSION_TEXT = (CLAMAV_FIXTURES / "version.txt").read_text()

# A fixed, obviously-a-fixture timestamp -- never a real generation date --
# so the samples are byte-for-byte reproducible regardless of when this
# test (or the regeneration script below) actually runs.
FIXED_GENERATED_AT = "2026-01-01T00:00:00Z"

# Placeholder paths standing in for the real temporary directories this
# test scans --files/--project against, so the published samples never
# carry a real filesystem path from whatever host generated them.
PLACEHOLDER_PROJECT = "/Users/example/project"
PLACEHOLDER_FILES = "/Users/example/selected-files"
PLACEHOLDER_KB = "/Users/example/oss-security-kb"


def _brew_payload() -> str:
    return json.dumps({
        "formulae": [
            {
                "name": "curl",
                "full_name": "curl",
                "tap": "homebrew/core",
                "installed": [{"version": "8.0.0"}],
            },
            {
                "name": "openssl@3",
                "full_name": "openssl@3",
                "tap": "homebrew/core",
                "installed": [{"version": "3.6.2"}],
            },
        ],
        "casks": [],
    })


def _osv_payload(requirements_path: str) -> str:
    return json.dumps({
        "results": [
            {
                "source": {"path": requirements_path, "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
                        "groups": [
                            {
                                "ids": ["PYSEC-2023-74"],
                                "aliases": ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"],
                                "max_severity": "6.1",
                            }
                        ],
                        "vulnerabilities": [
                            {
                                "id": "PYSEC-2023-74",
                                "affected": [
                                    {
                                        "package": {"ecosystem": "PyPI", "name": "requests"},
                                        "ranges": [
                                            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}
                                        ],
                                    }
                                ],
                                "references": [
                                    {"url": "https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q"}
                                ],
                            }
                        ],
                    }
                ],
            }
        ],
        "experimental_config": {},
    })


def _generate(monkeypatch, tmp_path: Path, fmt: str) -> str:
    """Run the fixture scan through `main()` and return its rendered output.

    `tmp_path` needs real directories to resolve --files/--project
    against; their absolute paths are string-replaced with clean
    placeholders below, exactly as the original one-off generation
    script did.
    """
    monkeypatch.setattr(cli_module, "now_iso", lambda: FIXED_GENERATED_AT)
    # The published sample's "host": "Darwin" -- and reaching every
    # adapter at all, since supported_capabilities() is empty elsewhere --
    # must hold regardless of the actual host generating/verifying this
    # sample (e.g. a Linux CI runner comparing against the checked-in
    # files). Patched here directly rather than relying solely on
    # tests/conftest.py's force_darwin fixture, since _regenerate() below
    # calls this with a plain MonkeyPatch instance, not through pytest.
    # `platform.machine()` is pinned to 'arm64' too, so the published
    # sample's "architecture" stays deterministic on x86_64 CI runners
    # (Ubuntu/Windows) instead of reflecting their real CPU.
    monkeypatch.setattr(cli_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(cli_module.platform, "machine", lambda: "arm64")

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "requirements.txt").write_text("requests==2.19.0\n")
    requirements_path = str((project_dir / "requirements.txt").resolve())

    files_dir = tmp_path / "selected-files"
    files_dir.mkdir()
    flagged = files_dir / "installer.pkg"
    flagged.write_text("not a real payload -- sample data only\n")

    def which(name: str):
        return {
            "brew": "/opt/homebrew/bin/brew",
            "osv-scanner": "/opt/homebrew/bin/osv-scanner",
            "clamscan": "/opt/homebrew/bin/clamscan",
        }.get(name)

    monkeypatch.setattr(macos.shutil, "which", which)

    def fake_runner(argv, *, timeout, max_bytes, extra_env=None):
        if argv and argv[0] == "/opt/homebrew/bin/brew":
            return CommandResult(0, _brew_payload(), "", None)
        if argv and argv[0] == "/opt/homebrew/bin/osv-scanner":
            if argv[-1] == "--version":
                return CommandResult(0, "osv-scanner version: 2.5.1\n", "", None)
            return CommandResult(1, _osv_payload(requirements_path), "", None)
        if argv and argv[0] == "/opt/homebrew/bin/clamscan":
            if argv[-1] == "--version":
                return CommandResult(0, CLAMAV_VERSION_TEXT, "", None)
            if argv[-1] == "--help":
                return CommandResult(0, CLAMAV_HELP_TEXT, "", None)
            alert = f"{flagged.resolve()}: Eicar-Signature FOUND\n"
            summary = "----------- SCAN SUMMARY -----------\nScanned files: 2\nInfected files: 1\n"
            return CommandResult(1, alert + summary, "", None)
        raise AssertionError(f"unexpected runner call: {argv}")

    output = tmp_path / f"report.{fmt}"
    main_argv = [
        "scan",
        "--brew", "--kb", str(KB_ROOT),
        "--project", str(project_dir), "--online",
        "--files", str(files_dir),
        "--format", fmt,
        "--output", str(output),
        "--overwrite",
    ]
    cli_module.main(main_argv, runner=fake_runner)

    content = output.read_text()
    content = content.replace(str(project_dir.resolve()), PLACEHOLDER_PROJECT)
    content = content.replace(str(project_dir), PLACEHOLDER_PROJECT)
    content = content.replace(str(files_dir.resolve()), PLACEHOLDER_FILES)
    content = content.replace(str(files_dir), PLACEHOLDER_FILES)
    content = content.replace(str(KB_ROOT.resolve()), PLACEHOLDER_KB)
    content = content.replace(str(KB_ROOT), PLACEHOLDER_KB)

    if fmt == "json":
        # Re-serialize after the string replacement above so indentation
        # stays canonical even though every replaced path is safely
        # inside a JSON string value.
        content = json.dumps(json.loads(content), indent=2) + "\n"

    return content


TEXT_HEADER = (
    "# Sample report -- FIXTURE DATA ONLY, not a real scan\n"
    "#\n"
    "# Generated by tests/test_samples.py, which runs `tocsin.cli.main`\n"
    "# with an injected fake Runner and fixture JSON payloads for\n"
    "# Homebrew, OSV-Scanner, and ClamAV -- no real engine binary was\n"
    "# ever invoked, and no real host was scanned. Paths are\n"
    "# placeholders (/Users/example/...), not real filesystem locations.\n"
    "# Run `.venv/bin/python tests/test_samples.py` to regenerate both\n"
    "# sample files from this test's fixture inputs.\n"
    "#\n"
    "# Command shown: tocsin scan --brew --kb <oss-security-kb> \\\n"
    "#   --project <project> --online --files <selected-files> --format text\n"
    "\n"
)


@pytest.mark.skipif(
    os.name != 'posix',
    reason='report paths are OS-native; the published samples are POSIX renderings',
)
def test_text_sample_matches_published_report(monkeypatch, tmp_path, force_darwin):
    # force_darwin: the sample scan needs Darwin's capability set to
    # reach every adapter (supported_capabilities() is empty elsewhere) --
    # see tests/conftest.py. The published sample's "host": "Darwin" is
    # also only correct when this is forced regardless of the actual
    # host running pytest (e.g. a Linux CI runner).
    rendered = TEXT_HEADER + _generate(monkeypatch, tmp_path, "text")
    published = (SAMPLES_DIR / "report-sample.txt").read_text()
    assert rendered == published


@pytest.mark.skipif(
    os.name != 'posix',
    reason='report paths are OS-native; the published samples are POSIX renderings',
)
def test_json_sample_matches_published_report(monkeypatch, tmp_path, force_darwin):
    rendered = _generate(monkeypatch, tmp_path, "json")
    published = (SAMPLES_DIR / "report-sample.json").read_text()
    assert rendered == published


def _regenerate() -> None:
    """Overwrite docs/samples/report-sample.{txt,json} from this test's
    own fixture inputs. Run directly (`python tests/test_samples.py`),
    not via pytest."""
    import tempfile

    from _pytest.monkeypatch import MonkeyPatch

    mp = MonkeyPatch()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            text_content = TEXT_HEADER + _generate(mp, Path(tmp), "text")
        mp.undo()
        mp = MonkeyPatch()
        with tempfile.TemporaryDirectory() as tmp:
            json_content = _generate(mp, Path(tmp), "json")
    finally:
        mp.undo()

    (SAMPLES_DIR / "report-sample.txt").write_text(text_content)
    (SAMPLES_DIR / "report-sample.json").write_text(json_content)
    print(f"wrote {SAMPLES_DIR / 'report-sample.txt'}")
    print(f"wrote {SAMPLES_DIR / 'report-sample.json'}")


if __name__ == "__main__":
    _regenerate()
