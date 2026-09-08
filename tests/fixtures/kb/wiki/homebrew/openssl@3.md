# openssl@3 (homebrew)

**Registry:** Homebrew
**Stable Version:** 3.6.2 (Homebrew formula)
**30-day Installs:** 534,400 (Homebrew analytics; as of 2026-04-27)
**Repository:** https://github.com/openssl/openssl
**Security Contact:** https://www.openssl.org/community/omc.html
**Disclosure Policy:** https://www.openssl.org/policies/secpolicy.html
**Current Status:** baseline stub

## Audit History

| Date | Auditor | Scope | Methodology | Findings | Source |
|------|---------|-------|-------------|----------|--------|
| *No public proactive formula-specific audits on record yet.* | — | — | — | — | — |

## Known Vulnerabilities

| CVE / Issue | Severity | Description | Fixed in | Source |
|-------------|----------|-------------|----------|--------|
| Review pending | — | This page has not yet been populated with formula-specific advisory history. Start with upstream OpenSSL advisories, Homebrew formula update history, and related distro package timelines. | — | https://osv.dev/list?q=openssl |

> Note: OSV searches for `openssl` typically return upstream and distro-scoped package records (Debian, SUSE, openEuler, etc.), not Homebrew-scoped advisories.
> Treat OSV as an upstream/distro evidence source and separately confirm which versions Homebrew shipped.

*Formula page: https://formulae.brew.sh/formula/openssl@3*

## Security Posture Notes

- `openssl@3` is a high-value Homebrew anchor because many developer tools and local services rely on it directly or indirectly for TLS, certificate handling, and cryptographic primitives on macOS systems.
- Homebrew analytics currently report 534,400 installs over 30 days (as of 2026-04-27), which makes this formula useful as a site seed even though formula analytics are not equivalent to registry package downloads.
- The interesting future work here is not just upstream OpenSSL CVEs, but also how quickly Homebrew packaged fixes after upstream releases and whether formula-specific patching or lag ever created meaningful exposure windows.

## Dependencies of Note

- `curl`, `git`, and many language runtimes on macOS can inherit behavior from the local OpenSSL toolchain or linked libraries, making this a strong cross-link candidate once more Homebrew pages exist.

## Open Questions

- How often has the Homebrew formula lagged upstream OpenSSL security releases in a way that meaningfully affected users?
- Which advisories belong on the `openssl@3` formula page versus the upstream `openssl` Linux / source page?
- Should Homebrew pages track bottle rebuild timing and patch-level drift as first-class fields for the future Vercel site?

## Related Pages

- [[linux/openssl]]
- [[homebrew/index]]

---
*Last updated: 2026-04-27 | Sources: 4 (Homebrew formula API, formula page, upstream repository, OpenSSL security policy)*
