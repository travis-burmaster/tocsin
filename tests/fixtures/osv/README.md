# OSV-Scanner fixtures

All JSON/text fixtures here were produced by running the real
`osv-scanner` v2.5.1 binary (osv-scalibr 0.5.2, commit c84fa4568,
darwin_arm64) against a scratch project, not by hand-authoring OSV
records. Details are in `docs/evidence/osv-contract.md`.

- `findings.json` -- trimmed from a real `osv-scanner scan source --offline
  --no-resolve --format json` run against a `requirements.txt` containing
  `requests==2.19.0` and `urllib3==1.24.1`, with a populated PyPI-only
  offline database. The original run reported 1 result (the
  `requirements.txt` manifest), 2 packages (`requests`, `urllib3`), with
  10 and 24 vulnerabilities respectively. This fixture keeps both
  packages but trims each to its first 2 `vulnerabilities[]` entries and
  the `groups[]` entries that reference them; all ids, aliases, `affected`
  ranges, and `references` on the kept entries are the real, unmodified
  advisory data. Only each vulnerability's `details` prose was replaced
  with a short placeholder to keep the fixture small.
- `empty.json` -- a real `{"results": [], ...}` payload (rc 0, an empty
  scan directory with `--allow-no-lockfiles`, or the shape seen after a
  failed per-ecosystem database load).
- `null_results.json` -- a real `{"results": null, ...}` payload, seen
  with `--allow-no-lockfiles` against an empty directory (rc 0).
- `malformed.json` -- deliberately invalid JSON, for the unparseable-output
  path.
- `wrong_schema.json` -- valid JSON with an unrelated top-level shape
  (`{"vulns": []}`), for the schema-rejection path.
- `version.txt` -- the real `osv-scanner --version` output for the tested
  binary.
- `stderr_no_offline_db_pypi.txt` -- real stderr text (paths genericized)
  from an offline run against a directory missing the PyPI offline
  database, exiting 127 with the "no offline version of the OSV database
  is available" message this adapter matches on.

Nothing here is a live network fetch; the underlying binary and its
offline database used to generate these fixtures are not part of this
repository.
