# Security policy

Tocsin is a security scanner, so defects in it can hide real problems. Please
report suspected vulnerabilities privately.

## Reporting

Use GitHub's private vulnerability reporting for this repository
(Security tab, "Report a vulnerability"). Do not open a public issue for a
suspected vulnerability, and do not include live malware samples; the EICAR
test string is sufficient to demonstrate scanner behaviour.

Include the Tocsin commit or version, the command run, the redacted report
(JSON preferred), and what you expected instead. Reports about a scan that
completed cleanly while it should not have are the highest priority.

## Scope

In scope: anything that makes Tocsin report a clean or complete result when
it should not, execute untrusted content, follow symlinks outside the scan
scope, leak file contents or reports, run commands with an unsafe
environment, or write report files with permissive modes.

Out of scope: vulnerabilities in ClamAV, OSV-Scanner, Homebrew, or the OSS
Security KB themselves (report those upstream), and the completeness of any
advisory database.

## Supported versions

There is no release yet. Reports against the `main` branch are welcome.
