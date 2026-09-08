Malformed Formula

This hand-written fixture deliberately omits the required status field
and has a broken Audit History table (a data row with a mismatched
column count) to exercise read_kb's malformed-page handling.

## Audit History

| Date | Auditor | Scope |
|------|---------|-------|
| 2026-01-01 | someone broke this row |

## Known Vulnerabilities

| CVE / Issue | Severity | Description | Fixed in | Source |
|-------------|----------|-------------|----------|--------|
| (none on record) | — | — | — | — |
