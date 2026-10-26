# Breach-class patterns

Recurring attack *shapes* distilled from public breach-pattern data (Verizon
DBIR, CISA advisories, MITRE ATT&CK Groups/Software). These are patterns to
recognize and defend against — **not** an enumeration of every incident, which
is unbounded. Each pattern gives the typical kill chain, where it shows up in
evidence, and the control that breaks it. Offensive skills use these to know
what to look for; defend uses them to attribute and prioritize.

A pattern is a prior, not a verdict. Confirm the specific chain against the
target's own evidence before claiming it.

## 1. Web app exploitation → foothold

- **Chain:** T1190 exploit public-facing app (injection / deserialization /
  file upload) → webshell or RCE → T1053/T1505 persistence → discovery → exfil.
- **Evidence:** web access log 200s to injection/traversal/upload paths;
  new/modified files under web root; outbound from the web process.
- **Breaks it:** input neutralization at the sink (code-audit/ultron findings),
  upload content/location controls, egress filtering, file-integrity monitoring.

## 2. Stolen/weak credentials → valid-account access

- **Chain:** T1110 brute force or T1078 reused/leaked credential → login as a
  real user → T1098 add persistence → privilege escalation → lateral movement.
- **Evidence:** auth log failures-then-success, logins from new geo/ASN/time,
  new accounts or `authorized_keys`/MFA-exception changes.
- **Breaks it:** MFA, lockout/rate limiting, credential rotation, anomalous-login
  alerting, least privilege. **DBIR-consistent:** stolen credentials are among
  the most common breach entry vectors — prioritize auth hardening.

## 3. Phishing → execution → C2

- **Chain:** delivery → T1204 user execution of payload → T1059 scripting →
  T1071/T1573 C2 → T1041 exfil.
- **Evidence:** endpoint execution of office/script spawn chains, beaconing in
  proxy/DNS logs, new autoruns.
- **Breaks it:** attachment/link controls, macro/script restrictions, EDR,
  egress/DNS filtering and beacon detection, user reporting path.

## 4. Vulnerable dependency / supply chain (OWASP A03)

- **Chain:** T1195 compromised or known-vulnerable component already imported →
  exploit of the reachable vulnerable code path → foothold.
- **Evidence:** lockfile match to a CISA KEV / OSV advisory **and** the vulnerable
  code is actually imported and reachable; post-exploit artifacts as in pattern 1.
- **Breaks it:** dependency inventory + advisory monitoring, patch the reachable
  component, pin/verify integrity of build inputs. A lockfile match alone is a
  risk, not a confirmed intrusion.

## 5. Ransomware / destructive impact

- **Chain:** any foothold (1–4) → credential access → lateral movement →
  T1486 data encrypted / T1490 inhibit recovery / T1485 destruction.
- **Evidence:** mass file modification bursts, shadow-copy/backup deletion,
  disabled security tooling (T1562), ransom notes.
- **Breaks it:** offline/immutable backups tested for restore, segmentation,
  privileged-access limits, early lateral-movement detection. In response,
  **preserve evidence before containment** where the order is safe.

## 6. Insider / privilege misuse

- **Chain:** T1078 legitimate access used beyond authorization → T1005/T1530
  collection → exfil via sanctioned channel.
- **Evidence:** access to data outside role/need, unusual volume/time, use of
  legitimate export features.
- **Breaks it:** least privilege, access review, data-access logging and
  volume/anomaly alerting, separation of duties.

## Using patterns with the skills

- **code-audit / ultron (offense):** patterns 1 and 4 tell you which sinks and
  dependencies carry the highest real-world blast radius — weight the test plan
  toward them.
- **defend (response):** match observed artifacts to the closest pattern to
  hypothesize the next step to look for, then confirm from the target's own
  evidence. Map every claim to ATT&CK via `attack-mapping.md`.
- **defend (harden):** patterns 2, 4, 5 drive the highest-priority baselines —
  auth/MFA, dependency currency, and tested backups.
