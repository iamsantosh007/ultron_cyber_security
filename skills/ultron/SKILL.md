---
name: ultron
description: Find and reproduce vulnerabilities in a user's locally running web app or API. Use for a localhost pentest, local security assessment, or requests to prove vulnerabilities in a development server, optionally using its source code. Coordinates reconnaissance, focused testing, independent verification, and an evidence-backed report through Claude Code subagents when available. Runs host tools without requiring Docker or a hosted scanner. Supports explicitly identified user-owned private-LAN development targets; excludes public targets and source-only reviews without a running app.
---

# Ultron — local application pentest

Turn a local app's attack surface into reproducible findings and specific fixes. Follow **Recon → Plan → Test → Verify → Report**, inspired by PentAGI's orchestration pattern. You coordinate the engagement and own the final verdict; delegate independent work when useful and supported, or run the same workflow sequentially.

## Establish the engagement

Use the user's request and existing project context to identify the target, source directory, test accounts, and exclusions. An explicit request to test their local app is authorization for ordinary, bounded testing: do not ask for it again. Local addressing alone does not establish ownership of unrelated services.

Record a short scope manifest before active testing:

- **Targets:** exact HTTP(S) origins (scheme, host, port), allowed base paths, and resolved addresses. Default to the named loopback service (`localhost`, `127.0.0.1`, `[::1]`). Include a private-LAN development service only when the user identifies it as theirs and includes it in the engagement. A different port is a different target.
- **Access:** test-account aliases and roles, fixture ownership, and local credential-file references. Use two ordinary accounts for cross-user checks when available. Never put raw passwords, tokens, or cookies in the manifest or report.
- **Constraints:** exclusions, permitted test-data changes, request/time limits, and known external integrations. Derive limits from project guidance; otherwise start conservatively and record the chosen budget.
- **Artifacts:** project directory, a unique private run directory, and the final report path.

Do not actively test a public or third-party target under this skill. Explain the scope mismatch and continue any applicable local work. If a necessary target or boundary is unclear, ask one focused question; continue source inspection or other independent work while it is pending. Missing credentials limit authenticated coverage, not the whole engagement.

### Keep requests within scope

Validate parsed origins and resolved addresses, not hostname substrings. Pin hostname-based connections to approved addresses where supported; otherwise recheck and stop if resolution changes. Do not follow redirects automatically or inherit a proxy that routes local traffic externally. Apply the scope manifest to crawlers, browser navigation/subresources, scanner templates, callbacks, retries, and application-triggered requests. If a tool cannot enforce these boundaries, use a narrower tool.

A callback listener or browser test page may use another local port: record its exact origin and purpose as a test fixture before use. Bind listeners to loopback for same-machine tests; a LAN target needs an explicitly included, reachable private listener. Fixtures do not authorize scanning other local services. Inspect external redirect destinations without visiting them. Use local substitutes for email, payments, webhooks, metadata, and other external integrations.

Public documentation/advisory lookup is separate from target testing and is allowed when needed; send only component/version search terms, never private code, credentials, or findings.

## Execute the assessment

For concrete, copy-adaptable commands and an `Agent` dispatch example for each
phase below, see [references/playbook.md](references/playbook.md). Treat it as a
pattern, not a script: adapt hosts, ports, tools, and payloads to the engagement
and the scope manifest.

### 1. Recon

Read the reconnaissance section of [references/methodology.md](references/methodology.md). Establish reachability and normal responses before probing. Prefer routes, schemas, tests, and dependency lockfiles from the supplied project, then verify the reachable surface. Track observed endpoints separately from routes inferred from source.

Return a target map: stack and version evidence; endpoint methods and inputs; authentication, roles, and object ownership; trust boundaries; relevant features; and unknowns. Do not promise a complete inventory from a crawl alone.

For delegation, use **RECON** in [references/subagent-prompts.md](references/subagent-prompts.md). A small app can be mapped inline.

### 2. Plan

Build a compact matrix of endpoint clusters × relevant vulnerability classes. Prioritize authorization boundaries, authentication, sensitive data flows, and user-controlled inputs that reach interpreters or filesystem/network operations. Load only the applicable methodology sections.

For each slice record its hypothesis, endpoints, account/fixture needs, baseline/control, proof condition, owner, and status. Use `planned`, `running`, `tested`, `inconclusive`, `blocked`, `skipped`, or `not-applicable`; a tested slice may produce zero or more findings.

Partition by class for small surfaces or by endpoint cluster for larger apps. Share read-only recon; give each worker separate evidence files and test fixtures. Serialize tests sharing accounts, records, rate limits, or timing measurements. Fit concurrency to actual agent slots and the app's capacity; start with two independent workers when resources allow. Divide the total request budget across workers.

### 3. Test

Use **PENTESTER** in [references/subagent-prompts.md](references/subagent-prompts.md), or perform each slice inline if agents are unavailable. In Claude Code, use `Agent` with `subagent_type: general-purpose` when supported; adapt to the actual tool interface. Dispatch independent slices together, queue the rest, and do not let workers recursively spawn agents.

Compare a normal request, a controlled probe, and a negative control. Capture the exact request, role, fixture state, response, and observable effect. A scanner alert or suspicious code path is a candidate, not a confirmed exploit. Stop escalating once the defined impact is proven with the least invasive evidence.

Tools run on the host, so use disposable test records and harmless markers. Reading unrelated host files, bulk data extraction, destructive queries, persistent shells, brute force, and stress tests are outside ordinary verification. If additional impact or host changes are actually needed, describe the concrete action and obtain any missing authorization; keep testing independent slices.

Check tools with `command -v`; prefer existing HTTP/browser tools and project runtimes. Missing scanners usually permit manual testing. Do not install globally, use `sudo`, or run downloaded exploit code by default. If installation is necessary, explain the dependency and use a project-local environment with the required permission. Record actual tool versions and effective options; inspect scanner templates for callbacks, side effects, and rate/redirect controls before running them.

Stop or back off on instability, unexpected writes, or exhausted budgets. Pivot when a new hypothesis warrants it, rather than repeating equivalent failed payloads. Report the limitation if a slice remains blocked.

### 4. Verify

Independently reproduce **every** candidate promoted to confirmed, either yourself or with **VERIFIER** in the prompt reference. Re-establish prerequisites, use fresh fixtures where needed, compare the control, and check actual impact. Do not repeat an irreversible action to prove reproducibility; retain it as a candidate if safe independent verification is unavailable.

- **Confirmed:** the effect and violated security boundary are demonstrated and independently reproduced.
- **Candidate:** credible signal, but reproduction or impact remains incomplete; state the exact missing evidence.
- **Rejected:** expected behavior, artifact, or a disproven hypothesis; retain the reason in run notes.

Deduplicate by root cause and affected boundary. Keep severity separate from confidence. Version matches, missing headers, an HTTP 200, a reflected string, or one slow response alone do not prove the claimed exploit. Distinguish development-only settings from demonstrated deployment exposure.

### 5. Report and close

Follow [references/reporting.md](references/reporting.md). Write `SECURITY-FINDINGS.md` in the project directory, unless the user specifies another path. Preserve an existing report unless this is an explicit update; otherwise use a run-specific filename. Only the orchestrator writes the consolidated report.

Include confirmed findings ordered by severity, candidates separately, actual coverage and blockers, prioritized remediation, and cleanup status. No findings means “no confirmed vulnerabilities in the tested scope,” not that the app is secure.

Remove only the disposable fixtures and processes created for this run; preserve evidence and record anything left behind. Do not patch application code unless remediation is requested. Finish with the report path, confirmed counts, highest-priority fixes, and material coverage limits.
