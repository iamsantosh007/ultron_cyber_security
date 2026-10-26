# Local application testing methodology

Use only checks supported by the target map. The scope manifest, request budget, and allowed side effects apply to every technique and tool below. Prefer a focused request with a known proof condition over a broad scanner run.

## Reconnaissance

1. **Baseline:** check the specified origin and normal response with a short timeout and redirects disabled. Identify app health and whether test requests can reach production data or external services. Do not automatically start an unknown service, run migrations, or seed its database; inspect the project's instructions first.
2. **Source-assisted map:** inspect routes/controllers, API schemas, middleware, authorization checks, frontend API calls, and tests. Read the dependency lockfile or installed package metadata for resolved versions; a manifest constraint or server banner is not an exact runtime version.
3. **Runtime map:** visit known in-scope routes and schema endpoints. Expand discovery only where it adds coverage; bound wordlists, concurrency, and elapsed time. Avoid logout, deletion, or other state-changing links during crawling, even if they use GET. For browser crawling, intercept requests and block origins outside the manifest, including subresources.
4. **Identity and data:** map anonymous, ordinary-user, and privileged access; authentication mechanism; session lifecycle; ownership and tenant boundaries. Use supplied test identities or supported test-account creation. Missing accounts become explicit coverage limits.
5. **Features and boundaries:** note uploads/downloads, URL fetchers, template rendering, XML parsing, imports/exports, webhooks, admin functions, and external integrations. Never contact an integration merely because the source references it.

For each endpoint record:

| Field | What to capture |
|---|---|
| Surface | Method, path, content type, source location or runtime evidence |
| Inputs | Path, query, body, header, cookie, file fields; constraints |
| Identity | Required role, owner/tenant, observed enforcement |
| Behavior | Normal response, side effects, downstream services |
| Confidence | Observed, source-inferred, or inaccessible; unresolved assumptions |

## Proof discipline

Every test needs a normal baseline, a hypothesis, a minimal probe, and a control that could falsify the hypothesis. Change one relevant variable at a time. Use unique run markers to distinguish fresh effects from caches, stale fixtures, or previous workers.

Capture request/response evidence and the server/browser state that proves impact, with secrets removed. A successful status code can still contain an error; a rejected request can still have changed state. Inspect outcomes, not just status codes. Keep source evidence separate from runtime evidence.

## Access control, tenant isolation, and mass assignment

- Create or use distinct test objects owned by accounts A and B. Establish that B can legitimately access B's object, then try the same operation as A and anonymously. Repeat only for the relevant read/write/delete actions using disposable records.
- Check function-level authorization on privileged routes, role changes, exports, and nested resources. Test server behavior directly rather than relying on hidden UI controls.
- For mass assignment, add a privileged field to an otherwise valid request and inspect persisted state through an authoritative read. An echoed field does not show it was accepted.
- **Proof:** another identity can read a marked private object or cause an unauthorized state change. Use a control on an accessible object to rule out broken requests. Guessing arbitrary real IDs is unnecessary when fixtures establish ownership.
- **Fix:** enforce role, tenant, and ownership checks server-side for each operation; allowlist writable fields.

## Authentication and sessions

- Check login/logout, session rotation, expiry, recovery-token reuse, and role changes using test accounts. Exercise security-sensitive actions after logout rather than assuming any retained token is exploitable.
- For signed tokens, change a claim or signature and verify that the server rejects the token. Judge algorithms, keys, audience, and issuer against the actual trust model; decoding a token proves nothing about validation.
- For JWTs specifically, test the signature trust model directly: set `alg` to `none` (and case variants) and drop the signature; swap `RS256`→`HS256` and sign with the public key as the HMAC secret (algorithm-confusion); point `kid`/`jku`/`x5u` headers at an attacker-supplied key or traversal path. Each probe must be rejected. Proof is the server **accepting** a token it should not trust, not merely that a library can decode one.
- Use a small, recorded number of login attempts if rate-limit behavior is relevant. Stop on lockout; do not run password lists or offline cracking as a default check.
- **Proof:** a demonstrated authentication bypass or session/recovery behavior that violates the application's security contract. Stateless tokens may remain valid by design; explain the impact and intended revocation semantics.
- **Fix:** use verified token/session libraries, enforce expiry and trust constraints, make recovery tokens single-use, and apply appropriate session invalidation.

## SQL and NoSQL injection

- Trace database-bound inputs where source is available. Compare equivalent valid requests and a controlled pair that should produce different results only if input changes query structure. Operator-shaped JSON is relevant only where the backend accepts that structure.
- Prefer boolean or bounded result differences using seeded data. A syntax error alone is a lead. If timing is necessary, alternate multiple controls/probes with a short delay and run them serially; exclude load, network jitter, and rate limiting.
- **Proof:** repeatable attacker control over query semantics or access to a marked test record outside the intended query. Do not dump tables, write files, or invoke operating-system features to establish injection.
- **Fix:** parameterized queries and strict validation of accepted query operators and fields.

## Command injection and server-side template injection

- Identify inputs passed to subprocesses or template engines. Use a unique inert output marker or a harmless expression with a negative control; prefer observable output to delays.
- Distinguish template expression evaluation from full command execution. Expected evaluation in an intentionally sandboxed expression feature is not automatically a vulnerability.
- **Proof:** unintended interpretation of input in a privileged interpreter context. Report only the capability actually demonstrated; expression evaluation does not prove RCE.
- **Fix:** avoid shell interpretation, pass structured arguments, keep user input as template data, and constrain interpreter capabilities.

## Cross-site scripting

- Track a unique marker through reflected, stored, and DOM flows. Identify the exact HTML/attribute/JavaScript context and relevant escaping before choosing a probe.
- Use an inert execution marker in a browser, such as a controlled DOM change; do not read cookies, send callbacks externally, or alter unrelated application state. For stored XSS, use a disposable record and a separate viewer session where appropriate.
- **Proof:** script execution in the victim application origin through an attacker-controllable path. Reflection, HTML injection, or source containing a risky sink is only a candidate until execution is observed. Record CSP and browser context.
- If no browser is available, continue other slices and label the XSS runtime claim unverified.
- **Fix:** context-appropriate encoding, safe DOM APIs, and sanitization where HTML is intentionally supported.

## SSRF and XXE

- Add a controlled listener to the scope manifest. Give each request a unique marker and retain listener logs to distinguish server-originated requests from the test client or browser.
- Model the relevant forbidden destination with a local fixture. Do not probe real cloud metadata, arbitrary internal services, or third-party callback providers. Any redirect fixture must terminate at another approved fixture.
- For XML, use a minimal valid document and an inert external entity aimed at a fixture. Avoid expansion bombs. For file-read checks use a marked file deliberately placed outside the permitted application directory, accessible to the target and containing no sensitive data.
- **Proof:** server-side access that crosses an intended restriction. A listener hit from a feature explicitly designed to fetch arbitrary permitted URLs proves functionality, not necessarily SSRF. Explain which destination, protocol, or data boundary was bypassed.
- **Fix:** constrain destinations/protocols, validate connection addresses and redirect hops, and disable unnecessary external entity resolution.

## Path traversal and file upload

- For traversal, create a harmless marked file outside the intended serving root in a location the target can read. Test path normalization and encoded variants only where supported. Never use host secrets or unrelated user files as proof.
- For uploads, use minimal fixtures to test extension/content validation, storage location, serving headers, overwrite behavior, and access controls. Test active content only when the expected hosting context makes it meaningful; clean up uploaded records afterward.
- **Proof:** reading the out-of-root marker, overwriting a disposable fixture outside the permitted destination, or executing a harmless marker in an unintended server/browser context. A dangerous-looking extension alone proves no impact.
- **Fix:** canonicalize and constrain paths, use generated storage names, separate uploaded content from executable locations, and authorize each file operation.

## CSRF, CORS, and redirects

- **CSRF:** perform a disposable state change from a controlled browser origin with the victim's normal session. Account for SameSite cookies, Origin checks, token validation, and accepted content types. Different local ports are cross-origin but may be same-site: document that distinction and do not claim a cross-site bypass from a same-site-only test. A missing token alone is insufficient.
- **CORS:** prove that a browser at the test origin can read a marked protected response under realistic credential/preflight behavior. Header reflection or a successful curl request alone is insufficient; wildcard origins with credentials are not automatically browser-readable.
- **Redirects:** submit an inert destination such as `https://ultron.invalid/` and inspect `Location` without following it. For client-side redirects, block the outbound navigation and capture the attempted destination. Determine whether the redirect is unexpected and whether it enables a demonstrated security impact.
- **Fix:** enforce CSRF protections appropriate to the session model, constrain CORS origins, and validate redirect destinations.

## Business logic and exceptional conditions

- Follow the actual workflow: pricing, quotas, invitations, object lifecycle, approval, and role transitions. Try an out-of-order transition or a repeated operation using disposable data and a small bounded sequence.
- Use a local fake integration for payment/email/webhook flows. For a suspected race, first explain the state invariant, then use minimal bounded concurrency only if permitted; serialize unrelated workers.
- Check whether malformed or failed operations bypass checks or leave partial unauthorized state. Do not test resource exhaustion or denial of service by default.
- **Proof:** violation of an explicit business or authorization invariant, with before/after state and a valid control. Do not invent product requirements.
- **Fix:** validate transitions server-side, enforce invariants transactionally, and apply idempotency where the operation requires it.

## Insecure deserialization

- Identify inputs deserialized by native formats (Java `ObjectInputStream`, Python `pickle`, Ruby `Marshal`, PHP `unserialize`, .NET `BinaryFormatter`, YAML/`SnakeYaml` unsafe loaders). Source or framework evidence usually reveals the sink; a magic byte prefix in a cookie or body is a runtime lead.
- Prefer a non-destructive proof: a gadget that produces an observable, inert side effect (a unique DNS/HTTP callback to an in-scope listener, or a benign marker write to a disposable path). Do not run public gadget-chain exploit code or spawn shells by default; describe the chain and obtain authorization if command execution must be shown.
- Distinguish a parser error or format acceptance from attacker-controlled object instantiation. A changed response to a malformed blob is a lead, not proof.
- **Proof:** attacker-controlled deserialization that creates objects or triggers execution/side effects outside the intended data contract, demonstrated with the least-invasive gadget. CWE-502.
- **Fix:** avoid native deserialization of untrusted input; use data-only formats with schema validation, allowlist expected types, and sign/verify any serialized state that must round-trip through the client.

## GraphQL and API-specific checks

- If a GraphQL endpoint is in scope, check introspection (`__schema`) availability, then use the schema to map types, queries, mutations, and object owners. Treat every resolver as its own endpoint for authorization testing; the single URL hides many operations.
- Test object- and field-level authorization per resolver (BOLA/BFLA): request another tenant's node by `id`, and request privileged fields a role should not see. Check mutations for mass-assignment of protected fields.
- Probe depth/alias/batch amplification only as a *structural* observation with a tiny bounded query; do not run a resource-exhaustion or DoS payload. Note missing depth/complexity limits as a hardening gap unless a concrete abuse is demonstrated.
- For REST, apply the same per-object and per-function authorization discipline across `GET/POST/PUT/PATCH/DELETE`, numeric/UUID identifiers, and nested resources. Verify server-side enforcement, not client-hidden routes.
- **Proof:** a resolver or endpoint returns or mutates data across an owner/tenant/role boundary, shown with two test identities and a control. CWE-639, CWE-862/863.
- **Fix:** enforce authorization in each resolver/handler against the authenticated principal; disable introspection and verbose errors in production; apply query depth/complexity and rate limits.

## Configuration, exposure, and dependencies

- Check reachable debug endpoints, accidental file exposure, client bundles, error output, and sensitive response fields. Save the minimum redacted evidence; never use discovered secrets to access another service.
- Interpret headers, TLS, cookie flags, and debug settings in the observed local environment. A development server on HTTP does not establish a production vulnerability. Separate hardening suggestions from proven exposure.
- Identify exact dependency versions and advisory prerequisites from authoritative sources. Confirm the affected code is present and reachable. A version/advisory match is a dependency risk, not a reproduced application exploit; preserve that distinction when a runtime check is unsafe or unavailable.
- Do not turn missing logging, missing headers, or scanner severity into high-impact findings without a demonstrated consequence.

## Tools and taxonomy

For GraphQL, WebSocket, or AI features discovered in recon, load
[protocol and agent checks](api-and-agent-tests.md). Do not run those checks merely
because the framework supports a feature the application does not expose.

Start with available `curl`/HTTP clients, browser automation, source search, and small local scripts. Add a specialized scanner only when it improves a specific slice. Before use, inspect its installed version/help and selected checks for request volume, active side effects, external callbacks, automatic updates, and redirect behavior. Record substitutions; a missing branded tool does not by itself mean the vulnerability class was skipped.

Use vulnerability names throughout. Add CWE or a versioned OWASP category only when the mapping is supported; never mix category numbers from different editions. OWASP Top 10:2025 is the web-app taxonomy reference; the API Security Top 10:2023 is a separate list. This workflow is not an exhaustive compliance assessment of either list.

Default CWE anchors for the classes above (use the most specific one the evidence supports; drop it if the mapping does not fit):

| Class | CWE |
|---|---|
| Broken access control / IDOR / BOLA | CWE-639, CWE-862 (missing), CWE-863 (incorrect) |
| Mass assignment | CWE-915 |
| Authentication / session | CWE-287; CWE-384 (fixation); CWE-613 (expiration) |
| JWT signature/algorithm trust | CWE-347 |
| SQL / NoSQL injection | CWE-89 / CWE-943 |
| Command injection / SSTI | CWE-78 / CWE-1336 (CWE-94 if code eval) |
| Cross-site scripting | CWE-79 |
| SSRF / XXE | CWE-918 / CWE-611 |
| Path traversal / file upload | CWE-22 / CWE-434 |
| CSRF / CORS / open redirect | CWE-352 / CWE-942 / CWE-601 |
| Insecure deserialization | CWE-502 |
| Business logic / race (TOCTOU) | CWE-840 / CWE-367 |
| Sensitive exposure / debug / vuln deps | CWE-200 / CWE-489 / CWE-1395 |

Authoritative references, for the relevant check rather than blanket loading:

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/)
- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
