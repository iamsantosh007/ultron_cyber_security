# Evidence and reporting

For repeatable assessments, SARIF export or later retests, use the
[assessment ledger](../../../docs/assessment-format.md). Keep the prose report's
verdicts aligned with the validated records. The helper produces the finding and
coverage report; add engagement-specific prioritization and chain narratives with
explicit evidence links rather than inventing severity formulas.

Use a private run directory (for example, an OS-created temporary directory) for
working notes and sanitized evidence. Keep only credential-file references in
notes; do not copy secrets into prompts or proof files. Do not commit assessment
artifacts automatically. For a small engagement, a single Markdown run log plus
the final report is enough; add per-worker evidence files when parallel work needs
them. Record the artifact location so the user can retain it before temporary
files expire.

Only the orchestrator writes the consolidated report. Persist the scope manifest,
matrix, candidate verdicts, and cleanup list as work progresses so an interrupted
engagement can resume. Before resuming active testing, recheck target resolution,
app/build state, and credentials; preserve evidence from earlier runs separately.

## Report structure

1. **Summary:** target, run date, local build/commit when known, confirmed counts
   by severity, highest-priority fixes, and material limitations. Count candidates
   separately. Say when the assessment is incomplete.
2. **Scope and method:** exact origins/base paths, exclusions, account roles,
   source availability, permitted fixtures, tool versions, and effective budgets.
3. **Confirmed findings:** Critical → High → Medium → Low → Info. Deduplicate by
   root cause; list additional affected endpoints under the same finding.
4. **Candidates and observations:** unresolved leads with the evidence still
   needed; hardening suggestions and dependency advisories clearly distinguished
   from reproduced vulnerabilities.
5. **Coverage:** actual checks, results, and gaps. Use “no issue observed in these
   checks” rather than asserting a class or the application is secure.
6. **Remediation and cleanup:** specific fix order, regression checks, created
   fixtures/processes, cleanup outcomes, residual changes, and evidence location.

## Finding record

```markdown
### ULTRON-001 — [High] Descriptive title
- **Class:** Vulnerability name; optional supported CWE/versioned OWASP mapping
- **Status:** confirmed | candidate
- **Affected surface:** METHOD /path, input, role/tenant boundary
- **Prerequisites:** Fixture setup, account aliases, relevant build/configuration
- **Expected behavior:** The security boundary the application should enforce
- **Observed behavior:** The effect actually demonstrated
- **Reproduction:** Ordered setup, exact redacted request(s), and observation steps
- **Evidence:** Minimal response excerpt/state change; artifact path(s)
- **Control:** Comparable request that rules out an alternative explanation
- **Verification:** Independent replay result, or precisely what remains unverified
- **Impact and severity:** Attacker capability and affected data/actions; rationale
- **Remediation:** Specific server/client change and source location when known
- **Regression check:** Observable behavior that should pass after the fix
- **Cleanup:** Test records/processes removed or remaining
```

Replace the illustrative ID, severity, and field descriptions with the actual
finding. Use stable IDs within an engagement, including on later retests. Never
mark a candidate “fixed” without rechecking its original proof and control after
the change; record a blocked retest as unverified.

## Reproducible evidence without secrets

Preserve method, path, parameter names, meaningful payload bytes, response status,
and the marked data/state that proves impact. Replace authentication material with
clearly named environment-variable references or local credential-file references,
and explain how to obtain fresh test credentials. Do not fabricate redacted values
as though they were sent. Avoid shell-expanded inline payloads: use request-body
files or literal quoting where payloads contain shell syntax.

Pair screenshots with the request and browser context needed to reproduce them.
For timing claims, retain baseline/probe timings and the controls used. For
callbacks, record the run marker, source context, and listener log. For unauthorized
writes, show disposable fixture state before and after, then restore or remove it.

## Severity and coverage

Base severity on demonstrated impact, required access, reachability, and affected
data/actions. Explain when deployment assumptions could change it. Do not assign a
numeric CVSS score unless the vector and assumptions can be justified. Missing
hardening controls alone do not establish high severity.

Use this coverage table shape, omitting irrelevant rows rather than claiming every
category was assessed:

| Endpoint cluster / input | Class | Role / fixture | Check and evidence | Outcome | Limitation |
|---|---|---|---|---|---|

Distinguish `tested` from `inconclusive`, `blocked`, `skipped`, and `not-applicable`.
Include the reason and next prerequisite for each gap. A failed tool invocation is
not a completed test, and a successful scan is not evidence of exhaustive coverage.
