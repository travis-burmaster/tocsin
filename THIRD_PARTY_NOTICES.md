# Third-party content

Tocsin's own source code is licensed under the MIT License (see `LICENSE`).
The repository also carries small amounts of data produced by other projects.
Each item below keeps its original license; none of it is relicensed.

## OSS Security KB pages (test fixtures)

- Files: `tests/fixtures/kb/wiki/homebrew/curl.md`, `tests/fixtures/kb/wiki/homebrew/openssl@3.md`
- Source: https://github.com/travis-burmaster/oss-security-kb at commit `30f536b7a81a681c340b2a37e044089623741ccb`
- Author: Travis Burmaster (maintained with LLM assistance)
- License: Creative Commons Attribution 4.0 International (CC BY 4.0), https://github.com/travis-burmaster/oss-security-kb/blob/main/LICENSE
- Changes: none; byte-for-byte copies. See `tests/fixtures/kb/ATTRIBUTION.md`.

At run time Tocsin reads a user-supplied KB checkout and includes page paths,
status, dates, and source links in its reports together with the notice
above; it never redistributes KB pages.

## curl security advisory data

- File: `src/tocsin/data/curl-advisories.json` (six reviewed records) and the
  review notes in `docs/evidence/curl-advisories.md`
- Source: the curl project's machine-readable advisory feed,
  https://curl.se/docs/vuln.json, and the per-CVE pages it links, retrieved
  2026-09-08. Copyright (c) Daniel Stenberg and contributors.
- Content kept: advisory identifiers, aliases, affected and fixed version
  ranges, severity labels, publication and modification dates, source URLs,
  and one-line summaries. Applicability notes were written for Tocsin from
  the advisory text and are marked as such in the records.
- License status: curl and libcurl are distributed under the curl license
  (https://curl.se/docs/copyright.html). The curl website does not state a
  separate license for the advisory feed itself. Tocsin treats the feed as
  factual security data, cites its source in every record and in every
  report, and does not reproduce advisory prose beyond the summary line.
  Confirm terms with the curl project before any redistribution that goes
  further than this.

## OSV and PyPA advisory data (test fixtures)

- File: `tests/fixtures/osv/findings.json`
- Source: output of OSV-Scanner 2.5.1 against a scratch project, containing
  PyPA Advisory Database records (`PYSEC-*` identifiers with CVE and GHSA
  aliases) served through the OSV offline database.
- License: the PyPA Advisory Database is licensed under Creative Commons
  Attribution 4.0 International, https://github.com/pypa/advisory-database/blob/main/LICENSE.
  OSV-Scanner itself is Apache-2.0 and is not redistributed here.
- Changes: the fixture is trimmed to two vulnerabilities per package and each
  record's `details` prose is replaced with a placeholder; identifiers,
  aliases, affected ranges, and references are unmodified. See
  `tests/fixtures/osv/README.md`.

## ClamAV

Tocsin invokes a separately installed `clamscan` and never redistributes
ClamAV or its signature databases. ClamAV is GPL-2.0; its flag names quoted
in `docs/evidence/clamav-contract.md` come from the `clamscan(1)` manual.
The EICAR test string used in gated tests is the industry-standard harmless
test file published by EICAR.

## Homebrew inventory fixture

`tests/fixtures/homebrew/brew-info-installed.json` is a trimmed `brew info
--json=v2 --installed` capture. It contains only public formula metadata as
published by Homebrew (BSD-2-Clause).
