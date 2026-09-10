# Sample reports

`report-sample.txt` and `report-sample.json` are **fixture data, not a
real scan.** They are generated and verified by `tests/test_samples.py`,
which calls `tocsin.cli.main` directly with an injected fake `Runner`
(the same mechanism every adapter test in this project uses) and
hand-written/fixture JSON payloads for Homebrew, OSV-Scanner, and
ClamAV -- no real `brew`, `clamscan`, or `osv-scanner` binary is ever
invoked, and no real host's inventory, files, or project dependencies are
reflected anywhere in these files. That test compares its rendered
output to these two files byte-for-byte with a fixed `generated_at`
(`2026-01-01T00:00:00Z`, obviously a fixture value, never a real
generation date), so a change to `tocsin.report`'s text/JSON rendering
that isn't reflected here fails the test loudly instead of silently
drifting.

The equivalent command, against real installed engines and a real
project, would be:

```
tocsin scan --brew --kb /path/to/oss-security-kb \
  --project /path/to/project --online \
  --files /path/to/selected-files \
  --format text   # or --format json
```

## What's in the samples

- **`--brew`**: a fixture Homebrew inventory with two formulae --
  `curl 8.0.0` (matches five of the six reviewed curl advisory records,
  all `detected`, from `src/tocsin/data/curl-advisories.json`) and
  `openssl@3 3.6.2` (`unassessed`, with real KB context resolved against
  the KB fixture at `tests/fixtures/kb/`, itself an unmodified copy of a
  real OSS Security KB page -- see `tests/fixtures/kb/ATTRIBUTION.md`).
- **`--project --online`**: a hand-written OSV-Scanner JSON payload
  (shaped per `docs/evidence/osv-contract.md`'s "JSON keys consumed"
  section, not a captured real run) showing one `detected` finding for
  `requests 2.19.0` (CVE-2023-32681).
- **`--files`**: a fixture ClamAV run (using the `--help`/`--version`
  text in `tests/fixtures/clamav/`, plus a hand-written scan result). No
  ClamAV engine was ever available during development; those `--help`/
  `--version` fixtures were reconstructed by hand from the `clamscan(1)`
  man page, not captured from a real binary -- see
  `docs/evidence/clamav-contract.md`. The sample shows one `detected`
  finding (`Eicar-Signature`) for a placeholder path.

Paths in both files are placeholders (`/Users/example/...`); the test
runs against real `tmp_path` temporary directories, which are
string-replaced with these placeholders before comparing against the
published files. These paths -- and the placeholder substitution that
produces them -- are POSIX renderings, so the byte-for-byte comparison
in `tests/test_samples.py` only runs on macOS and Linux CI; it is
skipped on Windows, where scanning itself is unsupported by design.

## Regenerating

`tests/test_samples.py` is both the regression test and the generator.
After a deliberate, intentional change to `tocsin.report`'s rendering (or
to that test's fixture inputs), regenerate both files by running the test
module directly rather than through pytest:

```
.venv/bin/python tests/test_samples.py
```

This overwrites `docs/samples/report-sample.txt` and
`report-sample.json` with the test's own freshly rendered output. Then
re-run `.venv/bin/python -m pytest tests/test_samples.py -q` to confirm
it now passes, and review the diff to the two sample files before
committing -- an unexpected diff there is exactly the signal this test
exists to surface.
