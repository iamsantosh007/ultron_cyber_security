# Security Policy

## Scope of this policy

This policy covers the **Ultron plugin itself** — the skills, references, and
manifests in this repository. It does **not** cover the systems you test with
Ultron; those are your responsibility (see [Authorized use](#authorized-use)).

## Reporting a vulnerability

If you find a security issue in Ultron — a skill that could cause unsafe
behavior, a scope-enforcement gap, a prompt-injection path through reference
content, or a defect that could leak secrets — report it privately.

- **Preferred:** open a [GitHub security advisory](https://github.com/iamsantosh007/ultron_cyber_security/security/advisories/new) (private).
- **Email:** patrosantosh007@gmail.com with subject `ULTRON SECURITY`.

Please include the affected file, the behavior, and a minimal reproduction.
Do not open a public issue for an unfixed security defect. Expect an initial
response within a reasonable window; this is a community project, not a vendor
with an SLA.

## Authorized use

Ultron performs offensive and defensive security actions. **Use it only against
systems you own or are explicitly authorized in writing to test.** By design the
skills:

- default to loopback / explicitly-identified private-LAN targets and refuse
  public or third-party targets,
- avoid destructive, denial-of-service, mass-targeting, and data-exfiltration
  actions,
- gate live containment/eradication changes behind explicit authorization,
- handle incident evidence read-only and keep secrets out of reports.

These are safeguards, not a legal shield. You are responsible for staying within
your authorization and applicable law. Misuse is on the operator, not the tool.

## Handling of secrets and evidence

Ultron never commits findings or evidence (see [.gitignore](.gitignore)). Reports
redact credentials and reference them by location. If you extend Ultron, preserve
this: no raw secrets in prompts, logs, reference files, or committed artifacts.
