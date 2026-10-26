# Contributing to Ultron

Ultron is a Claude Code plugin with focused security skills and a standard-library
Python helper for assessment artifacts. Contributions are welcome: stronger checks,
better evidence, useful team workflows and corrections. Read this first so a change
fits the design.

## Design principles (do not regress these)

Ultron scores well because it is disciplined. Keep every contribution inside
these rails:

1. **Accurate evidence labels.** Runtime exploit confirmation needs a demonstrated
   effect and independent replay. Static issues remain explicitly static; incident
   observations need their own artifact evidence. Never relabel a scanner/version
   match as runtime proof or an absent retest as a fix.
2. **Scope discipline.** Default to loopback / explicitly-authorized targets.
   Never add a check that scans neighboring services, follows out-of-scope
   redirects, or contacts third parties. Enforce the scope manifest on every
   request, subresource, callback, and redirect.
3. **Least-invasive evidence.** Disposable fixtures, harmless markers. No table
   dumps, DoS, brute force, or destructive actions by default. Live
   containment/eradication stays authorization-gated.
4. **Secret hygiene.** No raw credentials, tokens, cookies, or PII in prompts,
   reference files, reports, or committed artifacts.
5. **Sharp and bounded.** Prefer a focused skill over a bloated one. "One stop"
   is many small skills auto-routed by their `description`, not one giant file.
   Keep each `SKILL.md` lean; put depth in `references/`.
6. **Cited knowledge.** Distill from public authoritative sources (OWASP, MITRE
   ATT&CK/CWE, NIST, CISA, PTES). Do not paste paywalled or pirated text. Add the
   source to `references/knowledge/sources.md`.

## Repository layout

```
.claude-plugin/{plugin.json,marketplace.json}   manifests
skills/<name>/SKILL.md                           one skill, with frontmatter (name, description)
skills/<name>/references/*.md                     the skill's depth
references/knowledge/*.md                          cross-skill shared packs
references/team-workflows.md                      assessment and handoff patterns
scripts/ultron.py                                 artifact helper, no PoC execution
scripts/validate_plugin.py                        offline package validation
docs/assessment-format.md                         ledger and CLI contract
tests/                                           behavioral regression tests
```

## Adding or changing a skill

- Give `SKILL.md` accurate frontmatter. The `description` is how Claude routes to
  the skill — make it specific, and distinct from the other skills so they do not
  collide. State when **not** to use it.
- Keep `SKILL.md` to the workflow; move catalogs, queries, and worked examples
  into `references/`.
- Link references with paths relative to the file. Keep cross-skill links working.
- Map findings to CWE / OWASP:2025 / ATT&CK using
  `references/knowledge/attack-mapping.md`; update the crosswalk if you add a class.

## Before opening a PR

- [ ] All internal Markdown links resolve.
- [ ] `plugin.json` and `marketplace.json` are valid JSON.
- [ ] No secrets, evidence, or findings committed (`.gitignore` covers the
      standard artifact names — check anything new).
- [ ] Version-sensitive facts (OWASP/ATT&CK edition, CVE) cite the current source.
- [ ] The change preserves the design principles above.

Verify the plugin still loads locally:

```sh
python3 scripts/validate_plugin.py
python3 -m unittest discover -s tests -v
claude plugin validate .claude-plugin/plugin.json --strict
claude plugin validate .claude-plugin/marketplace.json --strict
claude --plugin-dir /path/to/this/repo
```

Use Python 3.11+; keep runtime dependencies in the standard library. Test meaningful
invariants when changing the helper: scope containment, evidence integrity, verdict
requirements, export behavior and comparison semantics. The CI suite does not call
an LLM or pentest a live service. Do not publish evidence or automatically run scripts
embedded in a report. Version the manifest and helper together when releasing.

## License

By contributing you agree your contribution is licensed under the repository's
[MIT License](LICENSE).
