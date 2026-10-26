# Crosswalk: OWASP 2025 ↔ CWE ↔ ATT&CK

Shared mapping used by all Ultron skills. Offensive skills (ultron, code-audit)
label a finding with its OWASP:2025 category and CWE; the defensive skill
(defend) attributes observed activity to MITRE ATT&CK tactics/techniques. This
table bridges the two so a finding and an intrusion describe the same thing.

Use the **most specific** mapping the evidence supports; drop a column when it
does not fit. ATT&CK columns describe how a *weakness is exploited in the wild*,
not that exploitation occurred — keep the offense/defense distinction explicit.
Versions: OWASP Top 10:2025, CWE, MITRE ATT&CK v18 (Enterprise).

## OWASP:2025 → CWE → ATT&CK

| OWASP:2025 | Typical CWE | Exploitation (ATT&CK tactic · example technique) |
|---|---|---|
| A01 Broken Access Control (incl. SSRF) | 639, 862, 863, 918 | Initial Access / Discovery · exploit public-facing app (T1190); SSRF → cloud metadata (T1552.005) |
| A02 Security Misconfiguration | 200, 489, 548, 942 | Initial Access · T1190; Discovery · cloud/service config (T1580/T1526) |
| A03 Software Supply Chain Failures | 1395, 1104, 506 | Initial Access · supply chain compromise (T1195); Execution via dependency |
| A04 Cryptographic Failures | 327, 328, 311, 326 | Credential Access · unsecured credentials (T1552); Collection of data in transit |
| A05 Injection (SQL/NoSQL/cmd/SSTI/XSS) | 89, 943, 78, 94, 1336, 79 | Execution · command/script (T1059); exploit public-facing app (T1190) |
| A06 Insecure Design | 840, 657 | varies — logic abuse; no single technique |
| A07 Authentication Failures | 287, 347, 384, 613, 798 | Credential Access · brute force (T1110); valid accounts (T1078); T1212 |
| A08 Software or Data Integrity Failures | 502, 345, 494 | Execution / Persistence · insecure deserialization, unsigned update |
| A09 Logging & Alerting Failures | 778, 223 | Defense Evasion · impair/indicator removal (T1562, T1070) — enables dwell |
| A10 Mishandling of Exceptional Conditions | 755, 391, 209 | Discovery · error-message info leak (T1592/T1210 chains); DoS-adjacent |

## ATT&CK tactic order (v18 Enterprise, for timelines)

Reconnaissance → Resource Development → Initial Access → Execution →
Persistence → Privilege Escalation → Defense Evasion → Credential Access →
Discovery → Lateral Movement → Collection → Command and Control →
Exfiltration → Impact.

Attribute an observed artifact to the **earliest** supported tactic and trace
forward. A technique label is a hypothesis backed by a specific artifact, never
a conclusion from one log line.

## High-signal technique → detection source

| Technique | Where it shows up (see defend/references/ir-playbook.md) |
|---|---|
| T1190 Exploit public-facing app | web access/error log: anomalous path, 200 to injection/traversal payload |
| T1078 Valid accounts | auth log: login from new source/time; impossible travel |
| T1110 Brute force | auth log: many failures then a success from one source |
| T1059 Command/scripting | shell history, auditd/execve, Sysmon 1/4688 |
| T1053 Scheduled task/job (persistence) | crontab, systemd timers, scheduled tasks |
| T1098 Account manipulation | new accounts, `authorized_keys` additions, role grants |
| T1071/T1041 C2 / exfil over channel | proxy/firewall/DNS logs: beaconing, large/odd egress |
| T1562/T1070 Impair defenses / remove indicators | log gaps, cleared history, disabled auditing |

Use this to turn "the app has an injection bug" (offense, code-audit/ultron)
and "we saw T1190 against the app" (defense, defend) into one coherent story.
