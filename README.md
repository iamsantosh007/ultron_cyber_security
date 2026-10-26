<p align="center">
  <img src="assets/ultron-hud.svg" alt="Ultron application security for developer teams" width="100%">
</p>

<h1 align="center">Ultron++</h1>

<p align="center">
  <b>Application security that follows a finding through to a verified fix.</b><br>
  A Claude Code plugin for local web/API pentesting, source review, defense, and remediation retests.
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-ff6a4d">
  <img alt="Version" src="https://img.shields.io/badge/version-0.2.0-ff8a3d">
  <img alt="Skills" src="https://img.shields.io/badge/skills-4-49d08b">
  <img alt="Python" src="https://img.shields.io/badge/helper-Python_3.11%2B-5aa0ff">
</p>

## What changed in Ultron++

- **Think in trust boundaries.** Prioritize sensitive assets, build principal/action/owner matrices, and investigate attack chains with explicit evidence for each connecting step.
- **Keep the proof.** A private assessment ledger records findings, actual coverage, cleanup, and SHA-256 references to sanitized evidence. Confirmed runtime findings need a separate replay artifact and a legitimate control.
- **Close the loop.** The new retest skill distinguishes resolved, persistent, regressed, unverified, and untested findings. A finding disappearing from a report never means it was fixed.
- **Fit developer workflows.** Review PR diffs with surrounding guards/callers, produce concrete regression checks, export Markdown and SARIF, and compare runs using identities stable across title or source-line changes.
- **Represent uncertainty.** Static analysis stays labeled as static. Skipped checks, missing evidence, and unresolved candidates cannot silently become a clean gate result.
- **Go beyond REST.** Focused methodology covers GraphQL resolver boundaries, WebSocket message authorization, and AI tool/retrieval boundaries using controlled fixtures.

Ultron coordinates tools available in Claude Code. Its Python helper manages artifacts and preflight checks; it is not an autonomous scanner executable or a network sandbox. No Docker, hosted scanner, or additional API account is required by the plugin. Available tools and credentials determine assessment coverage.

## Skills

| Command | Job | Output |
|---|---|---|
| `/ultron:ultron` | Test an authorized local web app/API with recon, hypotheses, probes, controls, and independent verification | Runtime findings, evidence and coverage |
| `/ultron:code-audit` | Trace source or a diff through authentication, authorization and sensitive sinks | Static issues with source chains and specific fixes |
| `/ultron:retest` | Recheck an earlier finding against a patched local build | Fix/regression verdicts with fresh proof and controls |
| `/ultron:defend` | Analyze incident artifacts or review hardening against a threat model | Evidence-based incident timeline or prioritized hardening review |

Describe the task normally or invoke a command explicitly. Examples:

> Pentest localhost:3000. Two test tenants are available. Focus on order access and exports.
>
> Review this branch against main for security regressions; trace changed guards and callers.
>
> Retest ULTRON-003 on the patched local build and check sibling routes using the same guard.
>
> Analyze these copied access and application logs; distinguish observations from hypotheses.

## Install or try the checkout

In an interactive Claude Code session, install the published marketplace version:

```text
/plugin marketplace add iamsantosh007/ultron_cyber_security
/plugin install ultron@ultron
```

To test this checkout immediately, launch from its root:

```sh
claude --plugin-dir "$(pwd)"
```

Local edits do not update the published marketplace or an existing cached installation. Keep the plugin identifier `ultron`; Ultron++ is the name of the 0.2.0 feature release.

## Assessment artifacts

The optional helper needs Python 3.11+ and has no third-party Python dependencies:

```sh
python3 scripts/ultron.py init /tmp/orders-run --project orders-api --target http://localhost:3000/api
python3 scripts/ultron.py scope /tmp/orders-run http://localhost:3000/api/orders
# Perform the assessment and populate the ledger with real evidence.
python3 scripts/ultron.py validate /tmp/orders-run
python3 scripts/ultron.py report /tmp/orders-run --output /tmp/orders-report.md
python3 scripts/ultron.py report /tmp/orders-run --format sarif --output /tmp/orders.sarif
python3 scripts/ultron.py compare /tmp/orders-run /tmp/orders-retest
python3 scripts/ultron.py gate /tmp/orders-retest --fail-on high
```

See [assessment format and CLI](docs/assessment-format.md) for evidence records, stable identities, gate exit codes, and SARIF behavior. Reports never overwrite existing files. SARIF exports confirmed findings with real source locations by default; URL-only issues remain in Markdown. Static candidates require an explicit export option and retain their candidate label. The helper never executes reproduction steps or uploads artifacts.

Scope preflight checks exact origins, path boundaries and pinned DNS answers. The actual HTTP/browser/scanner tool must still enforce connection addresses, proxies, redirects and subrequests. Hash validation establishes artifact integrity, not the truth of an agent's claims. Review and redact artifacts before sharing; there is no automatic arbitrary-secret detector.

## Operating boundaries

Active pentests target the named loopback service or explicitly included user-owned private-LAN development service. Public targets, unrelated local services, destructive actions, and broad network pivots are outside this workflow. Use disposable accounts/data and local substitutes for consequential integrations. Source review and defensive artifact analysis do not require a running app.

The [knowledge atlas](references/knowledge/techniques-atlas.md) helps route related work; it is not a claim that every listed domain has a built-in scanner. Map findings to supported CWE/OWASP categories and observed activity to the appropriate ATT&CK edition. Version-sensitive references live in the [source index](references/knowledge/sources.md). Binary/firmware reverse engineering needs separate tooling.

## Validate the plugin

```sh
python3 scripts/validate_plugin.py
python3 -m unittest discover -s tests -v
claude plugin validate .claude-plugin/plugin.json --strict
claude plugin validate .claude-plugin/marketplace.json --strict
```

The test suite covers artifact tampering, proof requirements, scope boundaries, report escaping, SARIF filtering, baseline semantics and CLI exit codes. CI runs offline package checks and these behavioral tests on Python 3.11 and 3.14. These checks do not substitute for evaluating an actual agent-led assessment against a controlled application.

## Layout

```text
.claude-plugin/          Plugin and marketplace manifests
skills/                 ultron, code-audit, retest, defend
references/             Team workflows and shared knowledge
scripts/ultron.py       Local ledger, scope preflight, exports, comparison and gate
scripts/validate_plugin.py
                        Offline packaging/reference checks
docs/                   Assessment data contract and CLI guide
tests/                  Behavioral regression tests
```

[Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [MIT license](LICENSE)
