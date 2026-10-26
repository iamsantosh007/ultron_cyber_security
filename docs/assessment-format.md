# Assessment ledger and CLI

The bundled `scripts/ultron.py` requires Python 3.11+ and the standard library.
It records and validates assessment artifacts; it never scans, executes a PoC,
installs a tool, or uploads findings. Existing Markdown-only assessments still work.

Commands below run from the plugin checkout. When using an installed skill, use
the absolute bundled script path supplied by that skill; the working directory
belongs to the app being assessed. Do not store evidence inside the plugin cache.

## Start and scope

```sh
python3 scripts/ultron.py init /tmp/orders-assessment --project orders-api --target http://localhost:3000/api
python3 scripts/ultron.py scope /tmp/orders-assessment http://localhost:3000/api/orders
```

`init` creates a **new**, private directory with `assessment.json` and `evidence/`;
it refuses existing directories. Use the same `--project` identity on later runs.
Repeat `--target` for explicitly scoped origins. `--mode code-audit` allows no
runtime target; `--mode retest` creates a new runtime retest. `--allow-private` is
only for private-LAN targets already included by the user, not implied permission.

Scope preflight checks scheme/host/port, base-path boundaries and current DNS
answers against the recorded addresses. It rejects embedded credentials, public
addresses, metadata/link-local ranges, mapped IPv6 and ambiguous path encodings.
It makes no HTTP requests. DNS resolution is not transport pinning: configure the
actual client separately. For intentional traversal probes, inspect the raw
request and transport manually; the helper deliberately rejects ambiguous paths
and offers no allow-all switch. Treat addresses as scope data, not proof of ownership.

## Fill the ledger as work progresses

`assessment` records `id`, stable `project`, `mode`, timezone-bearing `created_at`,
build `revision`, `complete`, `allow_private`, and `targets`. `init` sets revision
to `unknown` and completion to false. Update both truthfully after recon/testing.
Do not erase blocked checks to make a gate pass.

Each coverage record has `id`, `surface`, `check`, `status`, `notes`, and an
`evidence` array. Status is `planned`, `running`, `tested`, `inconclusive`,
`blocked`, `skipped`, or `not-applicable`. Tested rows require evidence, including
negative results. A not-applicable row explains why the feature is absent.

Each finding needs these fields; this example is a **candidate**, not a claim
that a vulnerability exists in any application:

```json
{
  "id": "ULTRON-001",
  "rule_id": "CWE-639",
  "surface": "GET /api/orders/{id}",
  "boundary": "cross-tenant order read",
  "title": "Potential cross-tenant order access",
  "severity": "high",
  "status": "candidate",
  "validation": "static",
  "description": "The lookup appears to omit tenant scoping; trace upstream guards.",
  "impact": "If reachable, another tenant's private order could be disclosed.",
  "remediation": "Enforce the authenticated tenant in the lookup predicate.",
  "regression_test": "A cannot read B's order; both owners can read their own.",
  "location": {"path": "src/orders.py", "line": 42},
  "evidence": []
}
```

Use `info`, `low`, `medium`, `high`, or `critical` severity. Findings may be
`candidate`, `confirmed`, `resolved`, or `rejected`; validation is `static` or
`runtime`. Source `location` is optional and must be a real repository-relative
file and positive line. Omit it when only an endpoint is known.
The helper checks location syntax; the reviewer must verify that the file/line
exists in the assessed revision because the ledger does not contain the source tree.

The stable fingerprint uses **rule_id + surface + boundary**. Use route templates
or stable symbols, not fixture IDs. Keep the identity across retests even if the
title, severity or source line changes. Use a specific rule/boundary for distinct
root causes. Duplicate identities are rejected so the coordinator must consolidate
duplicates. A rule ID can be an internal identifier when a CWE mapping is uncertain.

## Evidence and independent verification

Save sanitized request/response/control observations under the run's `evidence/`
directory, then obtain a reference:

```sh
python3 scripts/ultron.py evidence /tmp/orders-assessment evidence/idor-probe.txt
```

The command returns `{"path": "evidence/idor-probe.txt", "sha256": "…"}`.
Use this object in a coverage/finding evidence array. No traversal or symlink
references are accepted. The validator rereads every referenced artifact and
checks the hash. Hashes establish byte integrity, not authorship or truth; an
attacker able to edit both the ledger and evidence could replace both.

For `confirmed`, include `validation: "runtime"`, nonempty finding evidence,
and these additional objects populated from actual execution:

```json
{
  "proof": {
    "steps": ["Create orders for test users A and B", "Read B's marked order as A"],
    "expected": "A is denied access to B's order",
    "observed": "B's marked private field was returned to A",
    "control": "Both owners could read their own marked orders"
  },
  "verification": {
    "result": "reproduced",
    "reproducer": "Separate replay with fresh fixtures; record who/how here",
    "control": "Legitimate owner control passed in the separate replay",
    "evidence": []
  }
}
```

The empty verification evidence array above is illustrative and **will fail**
validation for a confirmed finding. Add a real hashed artifact from the separate
replay; it must use a different path from the original proof. `resolved` requires
runtime evidence plus `verification.result: "not-reproduced"` and a passing
legitimate control. A missing route or broken login is not a passing control.
For candidates, optional verification results include `blocked` and `not-run`.

Record cleanup in the top-level `cleanup` array with `resource`, `status`
(`removed`, `retained`, `pending`), and `notes`. Preserve evidence; remove only
this engagement's disposable fixtures/processes. Redact secrets before hashing.
The helper does **not** automatically detect or redact arbitrary secrets.

## Validate, export and compare

```sh
python3 scripts/ultron.py validate /tmp/orders-assessment
python3 scripts/ultron.py report /tmp/orders-assessment --output /tmp/orders-report.md
python3 scripts/ultron.py report /tmp/orders-assessment --format sarif --output /tmp/orders.sarif
python3 scripts/ultron.py compare /tmp/orders-assessment /tmp/orders-retest
python3 scripts/ultron.py gate /tmp/orders-retest --fail-on high
```

Reports are created privately and never overwrite existing files. JSON comparisons
go to stdout. Rendered Markdown escapes active HTML and link syntax in record
values. Keep raw evidence separate and inspect it before sharing.

SARIF 2.1.0 includes only confirmed findings with source locations by default.
Use `--include-candidates` to include explicitly labeled candidate notes. Runtime
findings without a source location stay in Markdown; the SARIF run records the
omitted count. It does not invent file paths from endpoint URLs. A stable Ultron
fingerprint is included for compatible consumers; GitHub's upload action can add
the source-based `primaryLocationLineHash` GitHub uses for alert deduplication.
See [GitHub's SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).
No upload or issue publication happens automatically.

Comparison outcomes are `new`, `persistent`, `resolved`, `regressed`, `unverified`,
and `untested`. A finding absent from the second run is **untested**, never fixed.
Review differing builds/scope before interpreting a comparison; `new` includes
new candidates and does not imply confirmation.

Gate exit codes are intentionally distinct:

| Exit | Meaning |
|---|---|
| 0 | Completed recorded scope has no confirmed finding at/above the threshold |
| 1 | Confirmed finding meets the threshold |
| 2 | Invalid input, missing/tampered evidence, or file/operation error |
| 3 | Incomplete assessment, no executed checks, coverage gaps, or unresolved candidates |

Gate requires at least one `tested` coverage row. A source-only audit with unresolved
candidates cannot get a clean runtime verdict. Scope can deliberately be narrow,
so a passing gate is not a claim about the rest of the product.
