# Techniques atlas

A dense, navigable map of security domains — the breadth of a large technique
catalog captured in one orchestrated reference instead of hundreds of isolated
skills. Each row names the domain's scope, the signature techniques (with the
MITRE ATT&CK tactic/technique they fall under), the primary tooling, and **which
Ultron skill owns it** or where to hand off.

This atlas does not loosen Ultron's rules. Every technique here inherits the
same discipline: **authorized scope only, proof over alerts, least-invasive
evidence, secret hygiene, and authorization before any live containment or
destructive action.** Offensive rows are for authorized testing of systems you
own or may test; many are also listed so the defensive side knows what to detect.

- **Ownership key:** `ultron` (live pentest), `code-audit` (source review),
  `defend` (DFIR + harden), `REA` (install the reverse-engineer-anything plugin),
  `catalog` (deep per-technique drilldown — see the companion catalog in
  [sources.md](sources.md)).
- Map findings to ATT&CK/CWE/OWASP via [attack-mapping.md](attack-mapping.md);
  map defensive work to NIST CSF functions (Identify/Protect/Detect/Respond/Recover).

## Offense — application & network

| Domain | Signature techniques (ATT&CK) | Tools | Owner |
|---|---|---|---|
| Web application security | injection, XSS, SSRF, access control (T1190, T1059) | curl, browser automation, Burp-class proxy | ultron / code-audit |
| API security (REST/GraphQL/gRPC) | BOLA/BFLA, mass assignment, auth flaws (T1190) | schema tooling, HTTP clients | ultron / code-audit |
| Penetration testing (network) | service enum, exploitation, pivot (T1046, T1210) | nmap, netcat, service clients | ultron (in-scope hosts only) |
| Red teaming / lateral movement | valid accounts, remote services, pass-the-* (T1078, T1021) | auth tooling | catalog (authorized engagements) |
| Vulnerability management | reachability-confirmed advisory matching (T1190 precursors) | OSV, CISA KEV, SCA | code-audit / defend |

## Defense — DFIR, hunting, SOC

| Domain | Signature work (ATT&CK / NIST CSF) | Tools | Owner |
|---|---|---|---|
| Incident response | triage, timeline, containment (RS.*; T1070 evasion detection) | logs, grep/awk, timeline tooling | defend |
| Digital forensics | disk/memory acquisition, artifact analysis (DE.AE; T1005) | dd/dcfldd, Autopsy, Volatility, plaso | defend / REA |
| Threat hunting | hypothesis-driven detection, IOC sweep (DE.CM) | SIEM queries, Sigma, YARA | defend |
| SOC operations / detection engineering | alert triage, detection rules (DE.AE, PR.PT) | Sigma, Suricata, log pipelines | defend |
| Threat intelligence | IOC/TTP enrichment, attribution (TA0043/TA0042) | MISP, ATT&CK Navigator, OSINT | defend (data in, no active recon on third parties) |

## Cloud & container

| Domain | Signature work (ATT&CK) | Tools | Owner |
|---|---|---|---|
| Cloud security (AWS/Azure/GCP) | IAM misconfig, metadata SSRF, log analysis (T1552.005, T1078.004) | cloud CLIs, CloudTrail/Activity/GCP logs | code-audit (config) / defend (logs) |
| Container security | image CVEs, escapes, secrets in layers (T1610, T1611) | trivy-class scan, docker diff | code-audit / defend |
| Kubernetes | RBAC abuse, audit-log review, admission policy (T1078, T1609) | kubectl, audit logs, OPA | code-audit / defend |
| DevSecOps / CI-CD | pipeline injection, secret leakage, artifact integrity (T1195) | pipeline configs, SCA, SAST | code-audit |
| Supply chain security | dependency/build-input compromise (T1195.001/.002) | SBOM, signature verification | code-audit |

## Identity, crypto, zero trust

| Domain | Signature work (ATT&CK/CWE) | Tools | Owner |
|---|---|---|---|
| Identity & access management | token/session flaws, privilege boundaries (CWE-287/347; T1078) | auth tooling, JWT inspection | ultron / code-audit |
| Active Directory security | ACL abuse, Kerberos, DPAPI, shadow creds (T1558, T1555) | AD query tooling | catalog (authorized AD engagements) / defend (detect) |
| Cryptography review | weak algorithms, key handling, TLS config (CWE-327/311) | config inspection, tls dump | code-audit / defend |
| Zero-trust architecture | segmentation, least privilege, policy design (PR.AC) | architecture review | defend (harden) |

## Specialized

| Domain | Signature work | Tools | Owner |
|---|---|---|---|
| Malware analysis & reverse engineering | static/dynamic triage, unpacking, C2 config (T1027, T1055) | Ghidra, YARA, sandbox | **REA** + defend |
| Mobile security (Android/iOS) | app review, traffic intercept, storage (T1626) | apktool, objection, frida | REA / code-audit |
| Phishing defense | header/URL analysis, campaign triage (T1566) | header parsers, urlscan | defend |
| Ransomware defense | backup integrity, blast-radius limits (T1486, T1490) | backup audit, segmentation review | defend |
| OT/ICS & hardware/firmware | protocol exposure, firmware extraction (T0886 ICS; T1542) | firmware tooling | REA / defend (read-only, high caution) |
| AI / ML security | prompt injection, model/data integrity, extraction | app-level review | code-audit / ultron |
| Blockchain / smart contracts | reentrancy, access control, integer bugs (CWE-841) | solidity analyzers | code-audit |
| Compliance & governance | control mapping (NIST CSF, CMMC, ISO 27001) | framework crosswalks | defend (report), not a certification |

## How Ultron is a step up from a flat catalog

- **Orchestrated, not isolated:** three skills route into this atlas and hand off
  to each other (`code-audit` → `ultron` for runtime proof; either → `REA` for
  binaries) instead of hundreds of disconnected entries.
- **Proof-first everywhere:** a technique is run to *demonstrate and reproduce*
  an effect, never to emit an unverified alert.
- **Safety inherited by construction:** scope manifest, authorization gates, and
  secret hygiene apply to every row — they are not re-stated per technique.
- **Cited, not copied:** domain coverage distilled from public practice and the
  companion catalog in [sources.md](sources.md); map everything to ATT&CK/CWE/NIST
  so a finding and an intrusion describe the same thing.

For a deeper, tool-specific walkthrough of any single technique above, consult
the external companion catalog listed in [sources.md](sources.md), then bring the
result back under Ultron's proof and scope discipline.
