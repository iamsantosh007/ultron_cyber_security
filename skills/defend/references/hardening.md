# Hardening baselines

Per-component baselines and the high-impact misconfigurations to check first.
Rank findings by exposure × impact against the stated threat model — an
internet-reachable default credential outranks ten informational headers. Give
each recommendation an observable verification and, where risky, a rollback.

Authoritative baselines to cite rather than reinvent: CIS Benchmarks (per
component), vendor security guides, OWASP cheat sheets, and NIST SP 800-123/-52.
Confirm a setting in the *running* config, not only the sample/default file.

## Web server (nginx / Apache / reverse proxy)

- Server version and error pages not leaking build/stack; directory listing off.
- TLS: modern protocols only (TLS 1.2+), no weak ciphers, HSTS when HTTPS-only,
  valid cert, OCSP/chain correct. (`nginx -T`, `apachectl -S`, test with the
  server's own config dump — avoid scanning third-party TLS test services.)
- Request limits: body size, header size, timeouts set to curb abuse.
- Security headers where they reduce a real risk: `Content-Security-Policy`
  (biggest XSS-impact reducer), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy`, frame-ancestors/`X-Frame-Options`. Headers are defense in
  depth, not a substitute for output encoding.

## Application framework

- Debug/development mode **off** in production; stack traces not returned to clients.
- Secrets from environment/secret store, not source or world-readable config.
- Secure session cookies: `HttpOnly`, `Secure`, `SameSite` appropriate to the
  session model; rotation on privilege change; sane idle/absolute expiry.
- CSRF protection matching the session model; CORS restricted to known origins
  (never `*` with credentials).
- Authorization enforced server-side per operation (see code-audit / ultron);
  object/tenant ownership pushed into queries.

## Database

- Not bound to a public interface; reachable only from the app tier.
- No default/blank credentials; least-privilege app account (no DDL/superuser for
  runtime); separate admin account.
- Encryption in transit; backups encrypted and access-controlled; audit logging
  on for privileged actions.
- Verify: connect test from an unexpected network should fail; app account should
  be denied a privileged statement.

## Authentication & secrets

- Strong password/credential policy and lockout/rate limiting on auth endpoints.
- MFA on administrative access; service accounts scoped and rotated.
- Tokens: short-lived, verified signature + audience + issuer; revocation path
  exists. Recovery tokens single-use and expiring.
- No long-lived secrets in images, repos, CI logs, or environment dumps; use a
  secret manager; rotate anything exposed.

## Host / container

- Patch level current for internet-exposed services; unused services disabled.
- Least-privilege: no unnecessary SUID, containers not `--privileged`, root
  filesystem read-only where feasible, non-root runtime user.
- Egress filtering where exfil/C2 is in the threat model; inbound limited to
  required ports; host firewall default-deny.
- Logging shipped off-host so an attacker cannot trivially erase the trail;
  time sync (NTP) so timelines correlate.
- Container images: minimal base, no secrets baked in, pinned digests, scanned
  for known-vulnerable packages that are actually reachable.

## Prioritization rubric

1. **Exposed + exploitable now:** default creds, debug mode on prod, DB on public
   interface, missing auth on an admin route. Fix immediately.
2. **Weakens a real attack path:** permissive CORS, long-lived tokens, no egress
   filtering with sensitive data present.
3. **Defense in depth:** security headers, informational disclosure, verbose
   versions. Worth doing, not an emergency.

Do not inflate tier 3 into tier 1. Each recommendation states which tier and why.
