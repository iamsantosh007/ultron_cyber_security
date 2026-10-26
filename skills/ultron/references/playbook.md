# Worked playbook

Concrete, tool-agnostic examples for each phase. Commands assume an in-scope
loopback target `http://localhost:3000` and a source tree at `./server`. Adapt
hosts, ports, and tools to the actual engagement; the discipline matters more
than the exact binary. All examples use disposable data, unique run markers, and
inert destinations. Nothing here authorizes a target outside the scope manifest.

Use one run marker per engagement so fresh effects are distinguishable:

```sh
MARK="ultron-$(date +%s)-$$"   # e.g. ultron-1761500000-18423
RUN="$(mktemp -d)"                  # private run directory for notes + evidence
```

## 1. Recon

Baseline first — short timeout, redirects off, note status and shape:

```sh
curl --noproxy '*' -sS --connect-timeout 3 -m 5 -D - -o /dev/null --no-keepalive http://localhost:3000/
curl --noproxy '*' -sS --connect-timeout 3 -m 5 http://localhost:3000/health
```

Read resolved dependency versions from an npm v2/v3 lockfile; confirm the running
build uses that lockfile before calling them runtime versions:

```sh
test -f server/package-lock.json && jq '.packages | to_entries[] | select(.key != "" and .value.version != null) | {path: .key, version: .value.version}' server/package-lock.json
rg -n 'app\.(get|post|put|patch|delete)\(' --glob '!**/node_modules/**' server/   # route inventory from source
```

Record each endpoint in the methodology's surface table. Mark every row as
`observed` (hit it) or `source-inferred` (read it) — never conflate the two.

## 2. Plan

Build the slice matrix. One row per `endpoint cluster × class`, each with a
falsifiable proof condition:

```text
| slice | endpoints            | class            | accounts | control                | proof condition                         | status  |
|-------|----------------------|------------------|----------|------------------------|-----------------------------------------|---------|
| S1    | GET /api/orders/:id  | IDOR / BOLA      | A, B     | A reads A's own order  | A reads B's order marked $MARK          | planned |
| S2    | POST /api/login      | auth / JWT       | A        | valid token accepted   | tampered token authorizes a protected action| planned |
| S3    | GET /api/search?q=   | SQL injection    | A        | valid query returns seeded row  | boolean pair changes result set         | planned |
```

Prioritize authorization boundaries and inputs reaching interpreters. Serialize
slices that share accounts, records, or timing (S1 and any order-mutating slice).

## 3. Test

Each probe = baseline + probe + negative control. Example IDOR (S1), two
disposable orders owned by A and B:

```sh
# baseline: B reads B's own order (should succeed)
curl --noproxy '*' -sS --connect-timeout 3 -m 5 -H "Authorization: Bearer $TOKEN_B" "http://localhost:3000/api/orders/$ORDER_B"
# probe: A reads B's order (should be denied)
curl --noproxy '*' -sS --connect-timeout 3 -m 5 -H "Authorization: Bearer $TOKEN_A" "http://localhost:3000/api/orders/$ORDER_B"
# control: A reads A's own order (should succeed — proves A's token/path work)
curl --noproxy '*' -sS --connect-timeout 3 -m 5 -H "Authorization: Bearer $TOKEN_A" "http://localhost:3000/api/orders/$ORDER_A"
```

Finding only if the probe returns B's marked data while the control behaves
normally. Inspect the body, not just the status — a `200` can wrap an error and a
`403` can still have mutated state.

Put payloads with shell/SQL syntax in a file, never inline:

```sh
printf '%s\n' '{"q":"1\" OR \"1\"=\"1"}' > "$RUN/s3-probe.json"
curl --noproxy '*' -sS --connect-timeout 3 -m 5 -H 'Content-Type: application/json' --data @"$RUN/s3-probe.json" \
  http://localhost:3000/api/search
```

**Claude Code delegation** — dispatch independent slices as parallel workers
(see [subagent-prompts.md](subagent-prompts.md) for the full contracts):

```text
Agent(subagent_type="general-purpose",
      description="Ultron slice S1 IDOR",
      prompt=<shared contract> + <PENTESTER role, SLICE=S1, fixtures=ORDER_A/ORDER_B>)
```

Dispatch S1 and S3 together (independent); queue S2 if it shares account A's
session state. Workers never spawn their own agents.

## 4. Verify

Re-prove every candidate from a clean slate — fresh fixtures, independent run:

```sh
curl --noproxy '*' -sS --connect-timeout 3 -m 5 -H "Authorization: Bearer $TOKEN_B" \
  --data "{\"item\":\"$MARK\"}" -H 'Content-Type: application/json' \
  http://localhost:3000/api/orders > "$RUN/new-order.json"
ORDER_B2=$(jq -er '.id | select(type == "string" or type == "number")' "$RUN/new-order.json")
# Check that the ID is an expected identifier before using it as a URL path segment.
curl --noproxy '*' -sS --connect-timeout 3 -m 5 -H "Authorization: Bearer $TOKEN_A" \
  "http://localhost:3000/api/orders/$ORDER_B2" > "$RUN/replay-response.json"
```

Inspect the returned private fields and fixture ownership, then repeat the owner
control. A reflected marker in an error body is not a confirmed disclosure.

Do not repeat an irreversible action to prove reproducibility — keep it a
candidate and state the exact missing evidence. For a redirect, inspect without
following:

```sh
curl --noproxy '*' -sS --connect-timeout 3 -m 5 -D - -o /dev/null "http://localhost:3000/go?next=https://ultron.invalid/"   # read Location, do not visit
```

## 5. Report and close

Write `SECURITY-FINDINGS.md` (orchestrator only) using the record in
[reporting.md](reporting.md). Redact the token, keep the marker and the decisive
state change. Then clean up only what this run created:

```sh
curl --noproxy '*' -sS --connect-timeout 3 -m 5 -X DELETE -H "Authorization: Bearer $TOKEN_B" "http://localhost:3000/api/orders/$ORDER_B2"
# record anything that could not be removed as a residual change in the report
```

For structured output, use the [assessment helper](../../../docs/assessment-format.md)
to validate evidence and render Markdown/SARIF. The helper never executes these
example requests. Finish with the report path, confirmed counts, top fixes, and
coverage limits.
