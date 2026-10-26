# Authoritative sources

The knowledge in Ultron's skills is distilled from the public, authoritative
references below — not copied from them, and not from any paywalled or pirated
book. When a finding needs a citation, cite the primary source here, and prefer
the official page over a vendor blog. Verify version-sensitive facts (current
OWASP/ATT&CK edition, a specific CVE/advisory) against the live source at use
time; the notes here are current as of 2026-10-26.

## Taxonomies & frameworks

- **OWASP Top 10:2025** — web application risk list. A01 Broken Access Control
  (now includes SSRF), A02 Security Misconfiguration, A03 Software Supply Chain
  Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design,
  A07 Authentication Failures, A08 Software or Data Integrity Failures,
  A09 Logging & Alerting Failures, A10 Mishandling of Exceptional Conditions.
  https://owasp.org/Top10/ · https://top10.owasp.org/
- **OWASP API Security Top 10:2023** — separate list; do not mix numbering with
  the web Top 10. https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- **OWASP WSTG** (Web Security Testing Guide) — test procedures.
  https://owasp.org/www-project-web-security-testing-guide/
- **OWASP ASVS** — verification requirements / hardening targets.
  https://owasp.org/www-project-application-security-verification-standard/
- **OWASP Cheat Sheet Series** — per-topic prevention guidance.
  https://cheatsheetseries.owasp.org/
- **MITRE ATT&CK v18** (Oct 2025) — adversary tactics & techniques; Enterprise
  has 14 tactics. Used for attribution and detection-strategy mapping.
  https://attack.mitre.org/
- **MITRE CWE** — weakness taxonomy for findings. https://cwe.mitre.org/
- **MITRE CAPEC** — attack patterns. https://capec.mitre.org/

## Vulnerability & threat intelligence

- **NVD / CVE** — advisory and version data. https://nvd.nist.gov/
- **CISA KEV** — Known Exploited Vulnerabilities; prioritize these when a
  dependency match is in the catalog. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **GitHub Advisory Database / OSV** — package-level advisories for lockfile
  matching. https://github.com/advisories · https://osv.dev/

## Methodology & standards

- **PTES** — Penetration Testing Execution Standard. http://www.pentest-standard.org/
- **NIST SP 800-115** — technical security testing guide.
- **NIST SP 800-61** — computer security incident handling (DFIR).
- **NIST CSF 2.0** — Identify/Protect/Detect/Respond/Recover functions.
- **CIS Benchmarks** — per-component hardening baselines. https://www.cisecurity.org/cis-benchmarks
- **SANS Incident Handler's Handbook** — IR process reference.

## Breach pattern data (for incident-patterns.md)

- **Verizon DBIR** — annual breach pattern statistics (action/vector/asset).
- **CISA advisories & MITRE ATT&CK Groups/Software** — observed campaign TTPs.
- **MITRE Engenuity ATT&CK Evaluations** — technique-level adversary emulation.

These inform *patterns*, not an enumeration of every incident. Ultron distills
recurring attack shapes and their detections/preventions; it does not claim a
complete incident history.

## Companion catalog (external, optional)

For a deep, tool-specific walkthrough of a single technique beyond Ultron's
orchestrated skills, an external catalog of per-technique skills exists:

- **Anthropic-Cybersecurity-Skills** (mukul975), Apache-2.0 — 800+ narrow
  per-technique skills across ~30 subdomains, each ATT&CK/NIST-tagged.
  https://github.com/mukul975/Anthropic-Cybersecurity-Skills

Install it alongside Ultron when you want catalog-depth on one technique, then
bring the result back under Ultron's proof and scope discipline. Ultron's
[techniques-atlas.md](techniques-atlas.md) is an original, distilled map of the
same problem space — it was *inspired by* the breadth of such catalogs but is not
copied from them; no text or files are reused, and Ultron remains MIT-licensed.

