# Development setup and verification

This is the setup and verification guide for working on Tocsin from
source. It covers the Python environment, running the test suite,
`tocsin doctor`, installing the external engines Tocsin drives but never
installs itself, keeping their signatures/databases current, running the
optional real-engine integration tests, and the exit-code contract.
Tocsin itself never installs, updates, or fetches anything on its own --
every step below that touches an engine, a signature database, or the
knowledge-base checkout is something you run by hand.

## Prerequisites

- **Python 3.11 or newer.** macOS does not ship a usable `python3` by
  default (Xcode Command Line Tools' `python3` is a stub, or absent).
  Install one of:
  - Homebrew: `brew install python@3.13`
  - The official installer from https://www.python.org/downloads/macos/
- **macOS 13+ on Apple Silicon or Intel.** macOS is the only platform
  Tocsin scans today; see `docs/coverage.md` for exactly what has and has
  not been tested on each architecture.
- Never use the system `/usr/bin/python3` for development -- it is not
  guaranteed to have a compatible `venv`/`pip`.

## Create a virtual environment and install from source

```
python3.13 -m venv .venv
.venv/bin/pip install -e .[test]
```

This installs Tocsin in editable mode (so changes under `src/tocsin/`
take effect immediately) plus `pytest`. There are no other runtime
dependencies.

## Run the test suite

```
.venv/bin/python -m pytest -q -W error::ResourceWarning
```

Always use `.venv/bin/python`, never a bare `python`/`python3`, so tests
run against the environment you just created. `-W error::ResourceWarning`
turns any unclosed file/socket/subprocess into a test failure -- the
suite is expected to run clean under it.

A handful of tests are environment-gated real-engine integration tests
(see "Running the optional real-engine integration tests" below) and are
skipped unless you explicitly opt in. A handful of others are skipped on
non-POSIX platforms (Windows) because they exercise POSIX-only behavior
(file-mode bits, symlinks, process groups) -- see `docs/coverage.md` for
the full list and reasons.

## Run doctor

```
.venv/bin/tocsin doctor
.venv/bin/tocsin doctor --kb /path/to/oss-security-kb
```

`doctor` reports the host platform/architecture, the running Python
version, which scan capabilities are integrated for this platform, and
the discovery state of each external engine (`brew`, `clamscan`,
`osv-scanner`) on `PATH` -- version, missing, or a specific failure kind
-- without installing or invoking any of them beyond a bounded
`--version`/`--help` probe. `--kb PATH` additionally reports whether a
local knowledge-base checkout is readable and its snapshot commit.

## Installing the external engines Tocsin drives

Tocsin never installs, downloads, or updates any of these; it only
invokes an engine you have already installed and kept current yourself.

### ClamAV (`clamscan`), for `--files`

```
brew install clamav
freshclam          # downloads/updates the virus signature database
```

`freshclam` must be run manually, and re-run periodically to keep
signatures current -- Tocsin never invokes it. No clamscan binary or
signature database is shipped with, or fetched by, this project; see
`docs/evidence/clamav-contract.md` for exactly which behavior has been
verified against a real binary (currently: none -- see
`docs/evidence/validation.md`).

### OSV-Scanner (`osv-scanner`), for `--project`

```
brew install osv-scanner
```

or download the binary release matching the tested version from
https://github.com/google/osv-scanner/releases. **Tested version:
v2.5.1** (osv-scalibr 0.5.2) -- `scan_project`'s version guard only
accepts osv-scanner `2.5.x`; a different major/minor version is reported
`unavailable` by both `tocsin doctor` and a `--project` scan, naming both
versions. See `docs/evidence/osv-contract.md` for the full engine
contract.

#### Offline database

`--project` needs either `--online` (queries the OSV service directly;
see the privacy note below) or a local offline database directory via
`--osv-database PATH`. Populate that directory with osv-scanner itself:

```
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/path/to/osv-db
osv-scanner scan source --offline-vulnerabilities --download-offline-databases /path/to/some/project
```

This downloads the offline vulnerability databases for whatever
ecosystems that scan touches into `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`
(layout `<dir>/osv-scalibr/<Ecosystem>/all.zip`). Once populated, point
Tocsin at the same directory:

```
tocsin scan --project /path/to/project --osv-database /path/to/osv-db
```

Tocsin never runs `--download-offline-databases` itself and never
fetches a database on your behalf -- an absent or unpopulated
`--osv-database` path is reported `unavailable` without ever invoking the
engine.

### Homebrew (`brew`), for `--brew`

If you don't already have Homebrew, install it from
https://brew.sh/. Tocsin only ever runs `brew info --json=v2 --installed`
(read-only) and, in `doctor`, `brew --version`; it never runs
`install`/`upgrade`/`update`/`cleanup`.

## Obtain the OSS Security KB snapshot (optional, for `--kb`)

```
git clone https://github.com/travis-burmaster/oss-security-kb.git
```

`--kb PATH` is optional for every scope. Point it at a local clone (or
any checkout of the same layout) to get package context; without it,
package-bearing checks record KB context as `unavailable` and never
report a clean KB verdict. Tocsin never runs `git` inside a KB checkout
(a KB's own `.git/config` is untrusted input) -- it reads the current
commit via `.git/HEAD` and its ref files directly. Update your KB
checkout with an ordinary `git pull` when you want fresher context;
Tocsin never fetches it for you.

## Running the optional real-engine integration tests

Two tests are skipped by default and only run against a real installed
engine:

```
# ClamAV, against a real clamscan with a working signature database:
TOCSIN_CLAMSCAN=/opt/homebrew/bin/clamscan .venv/bin/python -m pytest tests/test_clamav.py -k real_clamscan -q

# OSV-Scanner, against a real binary and a populated offline database:
TOCSIN_OSV_SCANNER=/opt/homebrew/bin/osv-scanner TOCSIN_OSV_DB=/path/to/osv-db \
  .venv/bin/python -m pytest tests/test_osv.py -k real_osv_scanner -q
```

These are never run in CI (see `.github/workflows/tests.yml`) because CI
never installs a real engine or signature database. `docs/evidence/validation.md`
records which of these have actually been run, when, and with what result.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every requested check completed (`complete`), with no `detected`/`needs-review` findings. |
| 1 | Every requested check completed (`complete`), with at least one `detected` or `needs-review` finding. |
| 2 | At least one check was not `complete` (`partial`, `unavailable`, or `error`), or carried an `error`/`skipped` finding -- regardless of findings elsewhere. This also covers a cancelled scan (Ctrl-C). |

`unassessed` findings (coverage gaps -- a package or setting Tocsin has
no reviewed verdict for) never by themselves change the exit code; they
are visible in the findings list and in `metadata['coverage']` but do not
count as "actionable" the way `detected`/`needs-review` do, and do not
make a check incomplete the way `error`/`skipped` do.

## Privacy

By default, every scan operation is local. The only exception is
`--online` for `--project`, which transmits package names and versions to
the OSV advisory service. File contents and reports are never uploaded by
Tocsin. Reports (stdout or `--output`) are written with file mode 0600.
The same text is printed in `tocsin scan --help`.
