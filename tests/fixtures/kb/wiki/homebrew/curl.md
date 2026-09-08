# curl (Homebrew)

**Registry:** Homebrew
**Weekly Downloads:** unknown (Homebrew analytics blocked by network policy in this pass; curl is one of the most-installed Homebrew formulae)
**Repository:** https://github.com/curl/curl
**Security Contact:** curl-security@haxx.se
**Disclosure Policy:** https://curl.se/docs/security.html
**Current Status:** advisory-mapped

## Audit History

| Date | Auditor | Scope | Methodology | Findings | Source |
|------|---------|-------|-------------|----------|--------|

*No audits on record at the Homebrew-formula level. Upstream curl maintains its own security release history at https://curl.se/docs/vuln.html.*

## Known Vulnerabilities

The Homebrew `curl` formula tracks the upstream curl/libcurl release train directly without applying formula-specific patches. All security fixes are delivered by upgrading to the corresponding upstream release. The following advisories are the primary upstream records that affect the Homebrew formula; see [[linux/curl]] for the corresponding Linux-distro context.

| CVE / Issue | Severity | Description | Fixed in (upstream) | Source |
|-------------|----------|-------------|---------------------|--------|
| CVE-2023-38545 | High | SOCKS5 heap buffer overflow: too-long hostnames overflow a heap buffer in the SOCKS5 slow-path handshake; advertised by the curl team as "probably the worst curl security flaw in a long time"; affected all curl builds with SOCKS5 proxy support using hostnames > 255 bytes | curl 8.4.0 | [curl advisory](https://curl.se/docs/CVE-2023-38545.html) |
| CVE-2023-38546 | Low | Cookie injection: attacker can inject a cookie into a running transfer under specific conditions when curl is built with cookie support | curl 8.4.0 | [curl advisory](https://curl.se/docs/CVE-2023-38546.html) |
| CVE-2024-2004 | Low | Protocol selection bypass: `--proto -all,-http` disables all protocols but the default allowed set remains active, permitting unexpected plaintext requests | curl 8.7.1 | [curl advisory](https://curl.se/docs/CVE-2024-2004.html) |
| CVE-2024-7264 | Medium | `CURLINFO_CERTINFO` use-after-free: ASN.1 date parsing accesses freed memory when retrieving certificate information via libcurl | curl 8.9.0 | [curl advisory](https://curl.se/docs/CVE-2024-7264.html) |
| CVE-2024-8096 | Medium | OCSP stapling bypass: GnuTLS backend does not enforce OCSP stapling responses, allowing revoked certificates to pass verification; Homebrew curl uses OpenSSL, so macOS Homebrew installs are **not** affected by this specific issue | curl 8.10.0 | [curl advisory](https://curl.se/docs/CVE-2024-8096.html) |
| CVE-2025-0167 | Medium | Credential exposure in WHOIS: credentials transmitted in cleartext via WHOIS requests when `--proxy-anyauth` or similar options are in use | curl 8.12.0 | [curl advisory](https://curl.se/docs/CVE-2025-0167.html) |

*Upstream full history: https://curl.se/docs/vuln.html — curl publishes individual security advisories for every release cycle.*

## Security Posture Notes

**Homebrew vs system curl:** macOS ships `/usr/bin/curl` as part of the Xcode Command Line Tools, compiled against Apple's own TLS stack (SecureTransport / LibreSSL). Homebrew's `curl` formula is a separate installation at `/opt/homebrew/bin/curl` (Apple Silicon) or `/usr/local/bin/curl` (Intel), compiled against **OpenSSL** rather than LibreSSL. These two curl installations have distinct:
- Security patch cadences (Apple's backport cycle vs Homebrew tracking upstream releases within days)
- TLS backends (OpenSSL vs LibreSSL/SecureTransport, affecting which TLS-related CVEs apply)
- Default configurations and built-in protocol support

Scripts and tools that call `curl` without an absolute path pick up whichever appears first in `$PATH`. In typical Homebrew setups, Homebrew's curl takes precedence once `/opt/homebrew/bin` is added to PATH.

**Patch lag:** The Homebrew formula updates to new upstream releases very quickly — often within 1–2 days of an upstream security release. This is significantly faster than most Linux distribution backport processes. Users who `brew upgrade curl` promptly after security releases are generally well protected.

**CVE-2024-8096 / OCSP (OpenSSL vs GnuTLS):** This advisory only affects curl builds using the GnuTLS backend (common on Debian/Ubuntu). Homebrew's curl uses OpenSSL, so macOS Homebrew installations are not affected by this specific issue.

**CVE-2023-38545 (High severity):** The most significant recent vulnerability affected the SOCKS5 proxy hostname handling path. Because the Homebrew formula tracks upstream closely, updating to Homebrew curl 8.4.0 was sufficient to patch this vulnerability.

**Libcurl consumers:** Applications that bundle their own libcurl (rather than using the system-provided Homebrew-managed one) are not automatically updated when the Homebrew formula is upgraded. Embedded libcurl copies require separate tracking.

curl maintains a dedicated security team (curl-security@haxx.se), HackerOne bug bounty program, and a published coordinated disclosure policy. The upstream project has a strong security release cadence with typically quarterly security release batches.

## Dependencies of Note

- `openssl@3` — TLS backend for Homebrew curl on macOS; linked dynamically. See [[homebrew/openssl@3]]. OpenSSL CVEs may affect Homebrew curl independently of curl-specific advisories.
- `c-ares` — optional; Homebrew curl formula may enable async DNS via c-ares.
- `libssh2` — used for SCP/SFTP protocol support; libssh2 CVEs can propagate through curl.

## Open Questions

- What is the current Homebrew curl version (analytics API blocked in this pass)?
- Are there curl security releases after 8.12.0 (CVE-2025-0167) that should be added to this page? The upstream advisory page at https://curl.se/docs/vuln.html should be consulted on the next pass.
- Does the Homebrew formula's openssl@3 linkage introduce any runtime OpenSSL CVE exposure not tracked at the curl-formula level?

## Related Pages

- [[linux/curl]]
- [[homebrew/openssl@3]]
- [[homebrew/git]]
- [[homebrew/index]]

---
*Last updated: 2026-07-11 | Sources: 6 (curl.se security advisory trail via linux/curl cross-reference, CVE-2023-38545 through CVE-2025-0167)*
