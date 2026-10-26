# Worked playbook

Concrete, tool-agnostic examples for each phase. Commands assume an in-scope
loopback target `http://localhost:3000` and a source tree at `./server`. Adapt
hosts, ports, and tools to the actual engagement; the discipline matters more
than the exact binary. All examples use disposable data, unique run markers, and
inert destinations. Nothing here authorizes a target outside the scope manifest.

Use one run marker per engagement so fresh effects are distinguishable:

```sh
MARK="ultron-$(date +%s)-$RANDOM"   # e.g. ultron-1761500000-18423
RUN="$(mktemp -d)"                  # private run directory for notes + evidence
```

## 1. Recon

Baseline first — short timeout, redirects off, note status and shape:

```sh
curl -sS -m 5 -D - -o /dev/null --no-keepalive http://localhost:3000/
curl -sS -m 5 http://localhost:3000/health
```

Resolve the exact runtime version from the lockfile, not a manifest range:

```sh
test -f server/package-lock.json && jq '.packages[""].dependencies // {}' server/package-lock.json
grep -RnoE 'app\.(get|post|put|patch|delete)\(' server/ | head -40   # route inventory from source
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
| S2    | POST /api/login      | auth / JWT       | A        | valid token accepted   | alg:none / HS-RS confusion token accepted| planned |
| S3    | GET /api/search?q=   | SQL injection    | A        | q=1 vs q=1' same rows  | boolean pair changes result set         | planned |
```

Prioritize authorization boundaries and inputs reaching interpreters. Serialize
slices that share accounts, records, or timing (S1 and any order-mutating slice).

## 3. Test

Each probe = baseline + probe + negative control. Example IDOR (S1), two
disposable orders owned by A and B:

```sh
# baseline: B reads B's own order (should succeed)
curl -sS -m 5 -H "Authorization: Bearer $TOKEN_B" http://localhost:3000/api/orders/$ORDER_B
# probe: A reads B's order (should be denied)
curl -sS -m 5 -H "Authorization: Bearer $TOKEN_A" http://localhost:3000/api/orders/$ORDER_B
# control: A reads A's own order (should succeed — proves A's token/path work)
curl -sS -m 5 -H "Authorization: Bearer $TOKEN_A" http://localhost:3000/api/orders/$ORDER_A
```

Finding only if the probe returns B's marked data while the control behaves
normally. Inspect the body, not just the status — a `200` can wrap an error and a
`403` can still have mutated state.

Put payloads with shell/SQL syntax in a file, never inline:

```sh
printf '{"q":"1\" OR \"1\"=\"1"}' > "$RUN/s3-probe.json"
curl -sS -m 5 -H 'Content-Type: application/json' --data @"$RUN/s3-probe.json" \
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
ORDER_B2=$(curl -sS -m 5 -H "Authorization: Bearer $TOKEN_B" \
  --data "{\"item\":\"$MARK\"}" -H 'Content-Type: application/json' \
  http://localhost:3000/api/orders | jq -r .id)
# confirmed only if A again reads the NEW marked order it does not own
curl -sS -m 5 -H "Authorization: Bearer $TOKEN_A" http://localhost:3000/api/orders/$ORDER_B2 | grep -q "$MARK" \
  && echo CONFIRMED || echo "not reproduced"
```

Do not repeat an irreversible action to prove reproducibility — keep it a
candidate and state the exact missing evidence. For a redirect, inspect without
following:

```sh
curl -sS -m 5 -D - -o /dev/null "http://localhost:3000/go?next=https://ultron.invalid/"   # read Location, do not visit
```

## 5. Report and close

Write `SECURITY-FINDINGS.md` (orchestrator only) using the record in
[reporting.md](reporting.md). Redact the token, keep the marker and the decisive
state change. Then clean up only what this run created:

```sh
curl -sS -m 5 -X DELETE -H "Authorization: Bearer $TOKEN_B" http://localhost:3000/api/orders/$ORDER_B2
# record anything that could not be removed as a residual change in the report
```

Finish with: report path, confirmed counts by severity, highest-priority fixes,
and material coverage limits.
