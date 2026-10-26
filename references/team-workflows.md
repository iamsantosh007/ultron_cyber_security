# Developer-team assessment workflows

Use these patterns when the request benefits from them; the user's actual scope
and time budget take precedence. Keep run state outside the installed plugin.

## Choose depth from the job

| Job | Focus | Honest stopping condition |
|---|---|---|
| Quick check | One changed feature or highest-risk trust boundary | Planned checks completed; explicitly list deferred surfaces |
| Standard assessment | Reachable surface, auth matrix, data flows, applicable classes | Matrix completed or each gap explained |
| Deep assessment | Standard plus alternate roles, workflow abuse, adjacent paths and plausible chains | Agreed budget or evidence-based coverage boundary |
| PR/diff review | Changed entry points plus relevant callers, guards and sinks | Reachability traced on both sides of the diff |
| Retest | Original proof, legitimate control, root-cause siblings | Per-finding resolved/persistent/regressed/unverified/untested verdict |

Default to a standard assessment when no depth is specified. Short time limits
reduce the scope, not the evidence needed to call something confirmed. Allocate
verification time before launching additional discovery workers.

## Form attack hypotheses from assets

Identify what matters: private customer records, administrator actions, balances,
tenant separation, signed artifacts, recovery flows. For each trust boundary,
write: attacker capability → entry point → missing control → expected impact →
minimal proof → falsifying control. Use source to find reachable paths and runtime
behavior to test the claim. Revise the hypothesis when evidence contradicts it.

Example: an ordinary tenant member changes an order ID and reads another tenant's
marked order because the lookup has no tenant predicate. Proof uses two disposable
orders; owner reads establish the control. No bulk enumeration is needed.

Keep a hypothesis ledger with status and evidence. Record rejected hypotheses as
brief notes so another worker does not repeat the same failed assumption.

## Authorization matrix

For each sensitive action, record the expected and observed result:

| Principal | Own object | Same-tenant peer object | Other-tenant object | Admin function |
|---|---|---|---|---|
| Anonymous | Derive from product rules | Derive from product rules | Derive from product rules | Derive from product rules |
| Ordinary user | Derive from product rules | Derive from product rules | Derive from product rules | Derive from product rules |
| Tenant admin | Derive from product rules | Derive from product rules | Derive from product rules | Derive from product rules |

These cells are questions, not universal deny/allow rules. Record fixture owner,
actor, role, verb, tenant, expected behavior, observed state, and evidence. Test
read and mutation separately; a denied response may still have changed state.

## Attack chains without inflated claims

Connect findings when the output of one establishes the next step's actual
precondition. A chain record names step IDs, identity before/after each step,
evidence of the connecting condition, and the final demonstrated business effect.
Label the entire chain hypothetical if a linking step is untested. Two confirmed
weaknesses do not automatically prove that they can be chained.

Use harmless markers and local fixtures for the whole chain. Stop at demonstrated
impact; no persistent access, data dumps, or unrelated network pivots. Do not count
both the chain and every step as independent issues when they share the same fix.
Prioritize the earliest reliable control that breaks the chain.

## PR and diff review

Resolve the user's base/head or use a clearly stated local base. Read the diff and
relevant surrounding code on both sides. Follow changed routes to middleware,
callers, templates, sinks, and schema changes; an unchanged helper may be made
reachable by the patch. Distinguish introduced, pre-existing, and uncertain issues.
Account for renamed/deleted files and changed guards, not just added lines.

Example read-only commands, after verifying the refs exist:

```sh
git diff --no-ext-diff --no-textconv --find-renames BASE...HEAD --
git diff --no-ext-diff --no-textconv --name-status BASE...HEAD --
```

Replace BASE and HEAD with resolved refs as separate shell arguments; do not paste
untrusted branch names into shell code. Do not fetch, checkout, run repository
scripts, or publish a PR comment merely to read a diff. With no valid base, review
the available code and state the missing comparison.

## Remediation handoff

For each actionable issue include the owner/component, exact guard or sink to
change, why the current control fails, a minimal fix direction, a regression check,
and the proof/control to rerun. Where requested, write the failing regression test,
patch the root cause, run the relevant suite, and use the retest skill on a running
local build. A passing unit test alone does not establish the runtime exploit is
closed. Keep public issue/PR publication separate from local preparation.

## Team artifacts and CI

Use [the assessment format and helper](../docs/assessment-format.md) for persistent
identities, evidence hashes, Markdown/SARIF, baseline comparisons, and explicit
gate outcomes. Assign each worker its own evidence directory; only the coordinator
merges the JSON ledger. Machine validation checks record integrity and completeness,
not whether a human/agent told the truth about a request. Review artifacts before
sharing, including query strings and response bodies that could contain secrets.

Do not present the scope preflight as a firewall. Actual HTTP/browser/scanner
clients must enforce approved connections, redirect hops, proxies, and subrequests.
Application-triggered egress needs application/network controls or local substitutes;
client-side checks cannot contain it by themselves.
