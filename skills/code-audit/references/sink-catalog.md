# Sink catalog

Per-class sources, dangerous sinks, and the controls that neutralize a path.
A finding needs: an **attacker-controlled source** reaching a **sink** on a
reachable path with **no effective neutralizer** in between. A sink fed only by
constants or trusted server state is not a finding. Grep patterns locate
candidates; the trace decides.

## Untrusted sources (where attacker input enters)

HTTP request params/query/body/headers/cookies, path segments, uploaded file
name/content, `Referer`/`Host`/`X-Forwarded-*`, WebSocket frames, message-queue
payloads, deserialized objects, CLI args, environment on multi-tenant hosts,
and any database/field value that originally came from a user (second-order).

## SQL / NoSQL injection — CWE-89 / CWE-943

- **Sinks:** string-concatenated or f-string/template SQL; `db.query(...+input)`;
  `cursor.execute("... %s" % x)`; Mongo `find(JSON.parse(userInput))` or
  operator-shaped input (`{"$gt": ...}`); ORM `.raw()` / `.whereRaw()`.
- **Neutralizers:** parameterized queries / bound placeholders; ORM query
  builders with bound params; strict type coercion and operator allowlists for
  document stores.
- **Search:** `rg -n 'execute\(|\.raw\(|whereRaw|format\(.*SELECT|f"SELECT|\+ ?req\.|\$\{.*\}.*(SELECT|INSERT|UPDATE|DELETE)'`

## Command injection — CWE-78

- **Sinks:** `exec`, `system`, `popen`, `child_process.exec`, `os.system`,
  `subprocess.*(..., shell=True)`, backticks, and `eval` of a shell string.
  Java `Runtime.exec(String)` does not invoke a shell by itself; inspect actual
  executable/argument control rather than assuming shell metacharacters execute.
- **Neutralizers:** argument-vector APIs (`execFile`, `subprocess.run([...])`,
  `ProcessBuilder(list)`) with no shell, plus executable/argument validation.
  Argument-vector APIs still need protection against option injection and unsafe
  executables; use `--` where supported and constrain user-controlled arguments.
- **Search:** `rg -n 'shell=True|child_process\.exec\(|os\.system|Runtime\.getRuntime|popen\('`

## Code / template injection (SSTI, eval) — CWE-94 / CWE-1336

- **Sinks:** `eval`, `Function(...)`, `vm.runInContext`, `pickle.loads` of code,
  server-side template rendered from user string (`render_template_string`,
  Jinja/Twig/Freemarker/Velocity/ERB fed user input as *template* not *data*).
- **Neutralizers:** never compile user input as code/template; pass user values
  as template **context data**; sandbox with a capability-limited engine.
- **Search:** `rg -n '\beval\(|new Function\(|render_template_string|Template\(.*req|runInContext'`

## Cross-site scripting — CWE-79

- **Sinks:** `innerHTML`/`outerHTML`, `dangerouslySetInnerHTML`, `v-html`,
  `document.write`, `$(...).html(x)`, unescaped template interpolation
  (`{{{x}}}`, `| safe`, `| raw`, `HttpUtility`-bypassed output), `insertAdjacentHTML`.
- **Neutralizers:** framework auto-escaping left intact; context-correct output
  encoding; `textContent`/safe DOM APIs; sanitizer (DOMPurify) for intentional HTML.
- **Search:** `rg -n 'innerHTML|dangerouslySetInnerHTML|v-html|document\.write|\| ?safe|\| ?raw|\{\{\{'`

## Path traversal / file ops — CWE-22 / CWE-434

- **Sinks:** `open`/`readFile`/`sendFile`/`fs.*` with a path built from input;
  `path.join(root, userInput)` without containment check; archive extraction
  (`zip`/`tar`) writing member names unchecked (zip-slip); upload stored under a
  user-controlled name/extension in a served/executable directory.
- **Neutralizers:** canonicalize then verify the resolved path stays under an
  allowed root; generated storage names; served-content directory separate from
  executable paths; extension/content-type allowlist.
- **Search:** `rg -n 'sendFile|readFile\(|path\.join\(.*req|os\.path\.join\(.*request|\.\./|extractall|entry\.getName'`

## SSRF / XXE — CWE-918 / CWE-611

- **Sinks:** server-side `fetch`/`http.get`/`requests.get`/`curl`/`URL.open` on a
  user-supplied URL; webhook/callback/image-fetch/PDF-render features; XML
  parser with external-entity resolution enabled on user documents.
- **Neutralizers:** destination/protocol allowlist, DNS-rebinding and redirect
  re-validation, block link-local/metadata ranges; XML parser configured to
  disable DTD/external entities using the specific parser's documented controls.
  A generic secure-processing flag alone does not establish that every external
  resolver is disabled; inspect all parser entry points.
- **Search:** `rg -n 'requests\.(get|post)\(.*url|fetch\(.*req|URL\(.*input|DocumentBuilderFactory|XMLReader|etree\.parse|libxml'`

## Insecure deserialization — CWE-502

- **Sinks:** `pickle.loads`, `yaml.load` (unsafe loader), `Marshal.load`,
  PHP `unserialize`, Java `ObjectInputStream.readObject`, .NET `BinaryFormatter`,
  `JSON.parse` piped into a prototype-pollution-sensitive merge.
- **Neutralizers:** data-only formats with schema validation; `yaml.safe_load`;
  type allowlists / `ObjectInputFilter` where supported. Signatures establish
  provenance only if keys and all signing inputs are trusted; they do not make
  an unsafe deserializer safe when an attacker can influence signed content.
- **Search:** `rg -n 'pickle\.loads|yaml\.load\(|Marshal\.load|unserialize\(|readObject\(|BinaryFormatter'`

## Authorization / authentication — CWE-862/863/287/639

- **Patterns, not single sinks.** Look for: a handler missing the guard its
  siblings have; identity taken from the request (`req.body.userId`,
  `X-User-Id`) instead of the session; ownership/tenant check absent on one HTTP
  verb; role check on the client/UI only; direct object reference with no
  ownership filter in the query.
- **Neutralizers:** server-side authorization per operation against the
  authenticated principal; ownership/tenant predicate pushed into the data query.
- **Search:** `rg -n 'req\.(body|query|params|headers)\.(user|role|id|tenant|admin)|findById\(.*req|getById\('` then read the surrounding guard.

## Secrets & config — CWE-200 / CWE-798

- **Sinks:** hardcoded keys/passwords/tokens; private keys committed; debug
  flags; unsafe CORS origin reflection; verbose error leakage. A wildcard origin
  combined with credentials is rejected by browsers and is not by itself proof
  of a credentialed cross-origin read.
- **Search:** `rg -l 'AKIA[0-9A-Z]{16}|-----BEGIN .*PRIVATE KEY|secret\s*=|password\s*=|api[_-]?key\s*=' --hidden -g '!*.lock'`
- Report location and rotation need; list matching filenames instead of printing
  secret-bearing lines. Never use a discovered secret against a live service.

---

Grep locates; the **trace** confirms. For each hit, answer in order: is the
source attacker-controlled, does it reach the sink, is it neutralized on that
path, and is the sink authorized for that principal? Only a clean "no neutralizer,
reachable, unauthorized" chain is a finding.
