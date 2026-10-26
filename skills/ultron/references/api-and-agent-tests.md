# Protocol and AI application checks

Use only for features observed in the target map. The same identity matrix,
scope, request budget, proof controls and independent verification apply.

## GraphQL

Map resolvers from the schema/source and legitimate client queries. An exposed
schema or introspection endpoint is not itself a confirmed vulnerability.
Prioritize object access, field-level authorization, nested relations, mutations,
and privilege-bearing input fields. Test a marked object owned by B with A's
identity, including a nested traversal that reaches the same object. Compare the
same query as the owner. Inspect `errors` and partial `data`; HTTP 200 alone says
nothing about whether authorization worked.

Check aliases or batching with a small fixed number of ordinary operations to see
whether authorization or per-operation controls are skipped. Do not perform deep
recursion, huge batches, or resource-exhaustion tests by default. For limits, inspect
configuration and use bounded controls. Report only the actual bypass observed.

## WebSockets and event streams

Record the handshake, origin policy, authentication source, channel/topic ownership,
and message types. Use separate test identities and disposable channels. Verify
authorization for subscribe, read, and mutate messages, not just at connection time.
For role change/logout/expiry checks, specify the intended session contract before
calling retained access a flaw. Test reconnects without carrying stale fixtures.

For cross-site WebSocket hijacking, use a controlled browser origin and the victim's
normal cookie behavior. Prove a protected message can be read or action performed;
a successful handshake alone is insufficient. Record same-site versus cross-site
limitations of local fixtures. Keep frames small and connection counts bounded.

## AI features and agent tools

Identify which content is untrusted (chat input, retrieved documents, uploaded
files, external tool results), which tools can act, and which data belongs to each
user/tenant. Use a synthetic document containing an inert instruction marker to
test whether data can override the application's intended tool/data boundary.

Distinguish a model repeating attacker text from a security impact. Confirmation
needs an unauthorized tool action, cross-tenant synthetic-data disclosure, or a
violated application control, with application/tool logs and an ordinary control.
Use stubbed tools and synthetic records for consequential actions. Do not send
real secrets to a model/provider, attempt provider compromise, or treat the model's
own claim that it executed a tool as proof. Record nondeterminism and reproduce
with fresh sessions within the request budget.

For a retrieval boundary, seed a uniquely marked document for tenant B; show that
tenant A's normal retrieval is denied, then test the suspected bypass. For tool
authorization, compare requested arguments, server-enforced principal, and actual
side effects. A system-prompt leak alone is not equivalent to account compromise.
