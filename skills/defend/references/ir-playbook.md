# Incident response playbook

Log sources, high-signal queries, and artifact locations for reconstructing what
happened. Every query is **read-only**. Run against copies in `./ir-evidence`,
not the live subject. Pin each finding to a timestamped log line and source.

## Log source map

| Question | Primary sources |
|---|---|
| Who logged in / brute force / new account | `/var/log/auth.log`, `/var/log/secure`, `wtmp`/`btmp` (`last`, `lastb`), Windows Security 4624/4625/4720 |
| What ran | shell history, `auditd`, `/var/log/syslog`, process list, Windows Sysmon 1, 4688 |
| Web/app exploitation | access log, app error log, WAF/proxy log, framework request log |
| Persistence | `crontab -l`, `/etc/cron*`, systemd units/timers, `~/.ssh/authorized_keys`, `/etc/rc.local`, Run keys / scheduled tasks |
| Network / C2 / exfil | firewall log, proxy log, netflow, `ss -tunp`/`netstat` capture, DNS log |
| File changes | package manager verify, `find -newer`, mtime/ctime, integrity baseline if one exists |

## High-signal triage queries

```sh
# failed then successful login from same source (brute force → entry)
grep -E "Failed password|Accepted " ir-evidence/auth.log | awk '{print $1,$2,$3,$9,$11}'
# new unix accounts / sudo grants in the window
grep -E "useradd|usermod|new user|to root" ir-evidence/auth.log
# web requests that returned 200 to suspicious paths or long/encoded query strings
awk '$9=="200"' ir-evidence/access.log | grep -E "\.\./|%2e%2e|/wp-admin|\.php\?|union|select|cmd=|base64" 
# top talkers / unexpected outbound ports from a connection capture
sort ir-evidence/connections.txt | awk '{print $5}' | sort | uniq -c | sort -rn | head
# persistence sweep
cat ir-evidence/crontab.txt; grep -R . ir-evidence/systemd-units/ 2>/dev/null; cat ir-evidence/authorized_keys
```

Adjust field positions to the actual log format — confirm the format before
trusting an `awk` column. A `200` to an attacker path means the request
succeeded; read the response size and the following requests to judge impact.

## Host artifact locations

- **Linux:** `~/.bash_history` (and timestamps if `HISTTIMEFORMAT` was set),
  `/var/log/`, `/tmp` + `/dev/shm` for dropped payloads, `/proc/<pid>/exe` and
  `/proc/<pid>/cmdline` (live), `ls -la /etc/ld.so.preload`, SUID sweep
  `find / -perm -4000 -newer <marker> 2>/dev/null`.
- **Web app:** upload directories, session store, framework debug logs, recently
  modified source under the web root (`find <webroot> -type f -mmin -<window>`),
  unexpected `.php`/`.jsp`/webshell signatures in served paths.
- **Containers:** image history, mounted secrets, `docker diff <id>` for
  filesystem changes vs the image, orchestrator audit log.

## Artifact sources by platform

Extend the triage beyond a single host when the environment demands it. All
read-only; collect to `./ir-evidence` and hash. See the
[techniques atlas](../../../references/knowledge/techniques-atlas.md) for which
Ultron skill owns each platform.

- **Cloud control plane:** AWS **CloudTrail** (management + data events), Azure
  **Activity Log** / Entra ID sign-in & audit logs, GCP **Cloud Audit Logs**.
  Look for new IAM principals/keys, policy changes, `AssumeRole`/token use from
  new sources, and metadata-service abuse (SSRF → `169.254.169.254`, T1552.005).
- **Kubernetes:** API-server **audit log** (verb/user/resource), unexpected
  `exec`/`attach` into pods, privileged or `hostPath` pods, serviceaccount-token
  use, RBAC bindings added (T1609/T1078).
- **Containers:** image history and layers for baked-in secrets, `docker diff`
  for filesystem drift vs the image, orchestrator events, mounted secrets.
- **Windows / Active Directory:** Security log (4624/4625 logon, 4672 priv,
  4720 new account, 4768/4769 Kerberos), Sysmon (1 process, 3 network, 11 file),
  DPAPI master-key access, `authorized`-equivalent changes, suspicious ACL/DACL
  edits and shadow-credential (`msDS-KeyCredentialLink`) additions (T1558/T1555).
- **Evidence acquisition when a host must be imaged:** capture volatile state
  first (process list, network connections, logged-on users, memory) before
  disk; image with `dd`/`dcfldd` to a hashed file; analyze the **copy**, never
  the original. For memory, use the platform's accepted capture tool and analyze
  offline. Preserve the chain of custody (source, time, hash, handler).

## Timeline discipline

- Normalize all timestamps to one timezone (UTC) before correlating; note each
  source's native zone and any clock skew.
- Build the timeline from independent sources that agree; a lone artifact is a
  lead. Separate **observed** (a log line) from **inferred** (what it implies).
- Identify the earliest attacker-attributable event as the probable entry point,
  then trace forward to persistence, privilege change, lateral movement, and
  exfiltration. Missing logs are a coverage gap to state, not proof of absence.

## Attribution

Label activity with MITRE ATT&CK tactics in order — Initial Access, Execution,
Persistence, Privilege Escalation, Defense Evasion, Credential Access,
Discovery, Lateral Movement, Collection, Command and Control, Exfiltration,
Impact — and name the specific technique only when an artifact supports it. Use
the shared crosswalk at `../../../references/knowledge/attack-mapping.md`.
State the confidence and what evidence would raise it.
