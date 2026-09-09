# curl advisory snapshot (evidence)

Adapter: `src/tocsin/adapters/curl.py`. Snapshot: `src/tocsin/data/curl-advisories.json`
(symlinked at the repo root as `data/curl-advisories.json` for discoverability;
the packaged/importable location is inside `src/tocsin/data/` so
`importlib.resources` finds it whether Tocsin is run from an editable
checkout or an installed wheel -- `pyproject.toml`'s
`[tool.setuptools.package-data]` ships it as package data).

## Coverage is deliberately partial

Primary source: **https://curl.se/docs/vuln.json** (OSV schema 1.5.0),
retrieved 2026-09-08. That feed holds roughly **215** curl advisories
going back to curl's earliest releases. This snapshot ships exactly
**six** of them: the six CVEs the OSS Security KB's curl page
(`wiki/homebrew/curl.md`) cites. Each was individually reviewed against
the upstream feed (and, for one, the advisory's HTML page) rather than
promoted from KB or feed text alone. A `no-known-match` verdict from
`assess_curl` means "does not match one of these six reviewed records" --
it is never a claim that no curl vulnerabilities exist, and
`metadata['coverage_note']` on every result says so explicitly.

The feed does not structure applicability prerequisites (TLS backend,
protocol, build option): those live only in each advisory's prose and its
per-CVE HTML page. Turning that prose into a machine-checkable `requires`
qualifier is exactly the judgment call this snapshot exists to make
carefully and cite, rather than leaving to a generic string match.

Review date for every record below: **2026-09-08**. Reviewer of record:
"Tocsin maintainers (LLM-assisted review of upstream advisories)" (also
recorded in the snapshot file's `reviewer` field).

## Per-record review

### CURL-CVE-2023-38545 -- SOCKS5 heap buffer overflow

- Aliases: CVE-2023-38545
- Severity: **High** (feed `database_specific.severity`)
- Range: `>=7.69.0 <8.4.0` (feed `last_affected`: 8.3.0)
- Affects: both (tool and lib)
- Applicability qualifier: none -- Homebrew core builds curl's SOCKS5
  proxy support unconditionally, so no `requires` restriction applies.
- Published: 2023-10-11T08:00:00.00Z / Modified: 2026-05-19T11:21:50.00Z
- Sources: https://curl.se/docs/CVE-2023-38545.json ,
  https://curl.se/docs/CVE-2023-38545.html
- KB vs. feed: no disagreement.

### CURL-CVE-2023-38546 -- cookie injection with none file

- Aliases: CVE-2023-38546
- Severity: **Low**
- Range: `>=7.9.1 <8.4.0` (feed `last_affected`: 8.3.0)
- Affects: `lib` per the feed (libcurl's `curl_easy_duphandle` cookie
  handling)
- Applicability qualifier: none. The feed's `affects: lib` is *not*
  treated as a Homebrew applicability restriction -- the formula always
  ships both the `curl` tool and `libcurl` from the same build, so a
  lib-only flaw is still applicable to the installed formula.
- Published: 2023-10-11T08:00:00.00Z / Modified: 2026-04-25T17:48:46.00Z
- Sources: https://curl.se/docs/CVE-2023-38546.json ,
  https://curl.se/docs/CVE-2023-38546.html
- KB vs. feed: no disagreement.

### CURL-CVE-2024-2004 -- usage of disabled protocol

- Aliases: CVE-2024-2004
- Severity: **Low**
- Range: `>=7.85.0 <8.7.0` (feed `last_affected`: 8.6.0)
- Affects: both
- Applicability qualifier: none.
- Published: 2024-03-27T08:00:00.00Z / Modified: 2026-04-25T17:48:46.00Z
- Sources: https://curl.se/docs/CVE-2024-2004.json ,
  https://curl.se/docs/CVE-2024-2004.html
- **KB vs. feed disagreement:** the OSS Security KB's curl page states
  "Fixed in curl 8.7.1". The upstream feed's SEMVER range gives
  `fixed=8.7.0` with `last_affected=8.6.0`. This snapshot uses the
  upstream feed value (**8.7.0**), per primary-source precedence, and
  records the KB page's differing claim in the record's `notes` field.

### CURL-CVE-2024-7264 -- ASN.1 date parser overread

- Aliases: CVE-2024-7264
- Severity: **Low**
- Range: `>=7.32.0 <8.9.1` (feed `last_affected`: 8.9.0)
- Affects: both
- Applicability qualifier: none.
- Published: 2024-07-31T08:00:00.00Z / Modified: 2026-05-19T11:21:50.00Z
- Sources: https://curl.se/docs/CVE-2024-7264.json ,
  https://curl.se/docs/CVE-2024-7264.html
- **KB vs. feed disagreement:** the OSS Security KB's curl page states
  fixed=8.9.0. The upstream feed gives `fixed=8.9.1` with
  `last_affected=8.9.0` -- i.e. 8.9.0 is still affected. This snapshot
  uses the upstream feed value (**8.9.1**); the KB page is wrong on this
  point, and the record's `notes` field says so.

### CURL-CVE-2024-8096 -- OCSP stapling bypass with GnuTLS

- Aliases: CVE-2024-8096
- Severity: **Medium**
- Range: `>=7.41.0 <8.10.0` (feed `last_affected`: 8.9.1)
- Affects: both
- Applicability qualifier: **`requires.tls_backend = "gnutls"`**. The
  feed carries no structured backend field for this advisory; the
  qualifier comes from the advisory's own prose, confirmed by fetching
  https://curl.se/docs/CVE-2024-8096.html on 2026-09-08:
  > "This issue only exists when curl is built to use the GnuTLS library."
  > "The vulnerable code can only be reached when curl is built to use GnuTLS."

  Homebrew's core curl formula (`curl-formula.txt`: stable 8.21.0,
  deps including `openssl@3`, no GnuTLS/wolfSSL/mbedTLS/Schannel/
  SecureTransport) never builds against GnuTLS, so `assess_curl` resolves
  a `homebrew/core`-tap install to **no-known-match** for this record
  (backend known: openssl, required: gnutls, mismatch), and to
  **needs-review** for any install whose tap is not `homebrew/core` (backend
  unknown, cannot confirm absence of GnuTLS).
- Published: 2024-09-11T08:00:00.00Z / Modified: 2026-04-25T17:48:46.00Z
- Sources: https://curl.se/docs/CVE-2024-8096.json ,
  https://curl.se/docs/CVE-2024-8096.html
- KB vs. feed: no version-range disagreement; the qualifier itself is the
  point of this record.

### CURL-CVE-2025-0167 -- netrc and default credential leak

- Aliases: CVE-2025-0167
- Severity: **Low**
- Range: `>=7.76.0 <8.12.0` (feed `last_affected`: 8.11.1)
- Affects: both
- Applicability qualifier: none. The flaw requires a specific `.netrc`
  `default` entry shape at request time, not a specific build
  configuration, so it is not expressible as a `requires` restriction.
- Published: 2025-02-05T08:00:00.00Z / Modified: 2026-04-25T17:48:46.00Z
- Sources: https://curl.se/docs/CVE-2025-0167.json ,
  https://curl.se/docs/CVE-2025-0167.html
- KB vs. feed: no disagreement.

## Snapshot schema (as validated by `load_records`)

Top-level: `schema_version` (must be `1`), `package` (`"curl"`), `source`,
`source_retrieved`, `reviewed_at`, `reviewer`, `records` (list). No other
top-level keys are accepted.

Each record requires exactly: `id`, `aliases` (list of strings), `summary`,
`severity` (one of `Low`/`Medium`/`High`/`Critical`, matching the feed's
`database_specific.severity` vocabulary), `ranges` (canonical field: a
non-empty list of `{"introduced": ..., "fixed": ...}` objects, each
endpoint required to be a plain `MAJOR.MINOR.PATCH` string parseable by
`parse_release` -- this is where multi-range records would carry every
SEMVER range the feed lists, though none of the six shipped records need
more than one), `affects` (`tool`/`lib`/`both`), `requires` (object;
`{}` when nothing restricts applicability, currently only
`{"tls_backend": ...}` is understood by `assess_curl`), `withdrawn`
(`null` or a date string), `published`, `modified` (non-empty date
strings), `sources` (list of at least two `https://` URLs -- the per-CVE
JSON and HTML pages), and `notes` (string; empty unless there is a
KB-vs-feed disagreement or a qualifier's provenance to record).

There is deliberately no top-level `introduced`/`fixed` convenience field
in the *shipped* file -- `ranges` is required. `assess_curl` itself (given
an arbitrary `list[dict]`, not necessarily loaded from this file) also
accepts a flat `introduced`/`fixed` pair as shorthand for a single range,
so small ad hoc records in tests do not need to spell out `ranges`.

`load_records` raises `ValueError` on any deviation from this schema:
a missing or unexpected top-level key, the wrong `schema_version`, a
non-list `records`, a record missing a required key, an unrecognized
`severity`, or a range endpoint that does not parse as a plain release.
`tests/test_curl.py` exercises each of these rejections plus a full
validation pass over the real shipped file (`test_shipped_snapshot_*`).
