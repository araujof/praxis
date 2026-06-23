# cpex filter

The `cpex` filter embeds the [CPEX](https://github.com/contextforge-org/cpex)
policy runtime inside a Praxis HTTP filter. It resolves identity, evaluates
policies based on routes, consults a PDP (Cedar or CEL), mints delegated tokens,
and run actions (e.g., scans for PII, emits audit records, tracks session taint,
and rewrites request and response bodies). Everything runs in-process: the CPEX
runtime are Rust crates linked into the proxy.

It is feature-gated. Build with `--features cpex` to compile and register it.

## Why use this filter

A PDP or authorization rules engine answers one question: given this input, is the
action allowed? That verdict still has to be wired into something. Real authorization
resolves identity first, often consults more than one engine, mints a token for
the downstream call, strips sensitive fields from the payload, and writes an
audit record, in the right order with the right short-circuits. That
orchestration is normally bespoke code in every gateway.

CPEX makes the orchestration declarative. A policy is a per-entity chain of
steps. The PDP is one step in the chain, and the steps around it express the
rest: cheap predicates run first, the PDP runs only for requests
that clear them, `delegate(...)` mints a downstream-scoped token, `redact(...)`
rewrites a field on the wire, `run(...)` invokes a guardrail or audit plugin,
and `taint(...)` records a session label that a later request can act on.

## Where it sits in the chain

The filter consumes the metadata Praxis's built-in `mcp` filter produces, so the
`mcp` filter must run before it:

```text
mcp  ->  cpex  ->  router  ->  load_balancer
```

`mcp` parses the JSON-RPC body and writes `mcp.method` and `mcp.name` into filter
metadata. `cpex` reads that metadata to pick the matching policy route. With
`require_mcp_metadata: true` (the default) a request that reaches `cpex` without
`mcp.method` is rejected, which catches a chain that is missing `mcp` or has it
ordered after `cpex`.

## Configuration

The filter's fields sit directly under the `- filter:` entry. There is no
`config:` wrapper.

```yaml
filters:
  - filter: cpex
    config_path: /etc/praxis/cpex.yaml   # required
    body_access: read_write              # optional; default read_only
    require_mcp_metadata: true           # optional; default true
    init_timeout_secs: 30                # optional; default 30
    max_buffer_bytes: 10485760           # optional; default 10 MiB (read_write only)
```

| Field | Default | Purpose |
|---|---|---|
| `config_path` | required | Path to the CPEX policy document (the YAML below). Read once at startup; a parse or plugin-init error fails the build. |
| `body_access` | `read_only` | `read_only` buffers the body for inspection and discards mutations. `read_write` re-serializes field mutations (`redact`, `assign`) back into the request and response. |
| `require_mcp_metadata` | `true` | Reject any request that reaches the filter without `mcp.method` metadata. Set `false` only to front non-MCP traffic for identity-only enforcement. |
| `init_timeout_secs` | `30` | Time budget for `PluginManager::initialize` at startup (identity plugins fetch JWKS over HTTPS). On expiry the build fails fast. |
| `max_buffer_bytes` | `10485760` | Max body bytes buffered in `read_write` mode (10 MiB). Bounds per-request memory against oversized payloads. Ignored in `read_only` mode. |

## The policy document

`config_path` points at the CPEX policy. It has three parts: a `plugins` toolbox,
a `global` block, and a `routes` block. The routes are the policy; everything
else is what they pull from. Each route's `policy` is an ordered list of APL
(Authorization Policy Logic) steps.

```yaml
plugins:
  - name: jwt-user            # identity/jwt: validates X-User-Token
  - name: jwt-client          # identity/jwt: validates Authorization
  - name: workday-oauth       # delegator/oauth: RFC 8693 token exchange
  - name: pii-scan            # validator/pii-scan: PII detection
  - name: audit-log           # audit/logger: structured audit records

global:
  identity: [jwt-user, jwt-client]
  pdp:
    - kind: cel             # inline CEL expressions; use cedar-direct for Cedar

routes:
  - tool: get_compensation
    policy:
      - "require(role.hr)"
      - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
      - "taint(secret, session)"
      - "run(audit-log)"
    args:
      ssn: "str | redact(!perm.view_ssn)"
    result:
      ssn: "str | redact(!perm.view_ssn)"

  - tool: search_repos
    policy:
      - "require(team.engineering)"
      - cel:
          expr: |
            has(role.engineer) && role.engineer && args.visibility == "internal"
          on_deny:
            - "deny('engineering may read internal repos only', 'cel.policy_denied')"
```

### APL step vocabulary

| Step | Effect |
|---|---|
| `require(predicate)` | Deny unless the predicate holds. |
| `<predicate>: deny('reason', 'code')` | Deny with a reason and violation code when the predicate holds. |
| `cedar: { ... }` / `cel: { expr: ... }` | Consult the registered PDP. `on_allow` / `on_deny` attach reactions. |
| `delegate(plugin, target:, audience:, permissions:)` | Mint an audience-scoped token (RFC 8693) and attach it as an upstream header. |
| `run(name)` | Invoke a named plugin (PII scan, audit). `plugin(name)` is the same step. |
| `taint(label, session)` | Record a session label. See Sessions and taint. |
| `args.<field>: "... \| redact(...) \| mask(n)"` | Rewrite a request argument (needs `body_access: read_write`). |
| `result.<field>: "... \| redact(...)"` | Rewrite a response field on the way back. |

Steps run in order and the chain short-circuits on the first deny. Order
deliberately: place `run(audit-log)` before a step that may deny so the attempt
is recorded.

### PDP backends

The filter registers two PDP factories: `cedar-direct` (Cedar policy sets) and
`cel` (inline CEL boolean expressions). A route selects one with a `cedar:` or
`cel:` step; the global `pdp` block declares which engine is configured. Both are
compiled into the same binary.

The example above uses CEL. The Cedar form declares a policy set in the global
`pdp` block and calls it from a `cedar:` step, passing the resource built from
the request:

```yaml
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
        permit(principal, action == Action::"read", resource is Repo)
        when { principal.roles.contains("engineer") && resource.visibility == "internal" };

routes:
  - tool: search_repos
    policy:
      - "require(team.engineering)"
      - cedar:
          action: 'Action::"read"'
          resource:
            type: Repo
            id: ${args.repo_name}
            attributes:
              visibility: ${args.visibility}
```

CEL reads request attributes inline (`args.visibility`); Cedar takes them as an
explicit `resource`. Both reach the same allow or deny.

## Identity

Each `identity/jwt` plugin reads its own configured header (for example
`Authorization` for the client, `X-User-Token` for the user) and validates the
JWT against the issuer's live JWKS. One request can carry several identities at
once. The filter runs an early identity gate in the request phase: a request with
no valid token is rejected with HTTP 401 before the body is buffered.

## Sessions and taint

`taint(label, session)` records a label that persists across requests in the same
session. A later route reads it with `security.labels contains "label"` and acts
on it. This is a cross-tool, cross-request data-flow control: reading a secret in
one call can block sending mail in a later call.

The session is identified by the `X-Session-Id` request header. The filter maps
it to `agent.session_id`, and CPEX binds it to the resolved subject as
`H(subject : session_id)`. The same session id under a different subject is a
different bucket, so taint never crosses principals. When the header is absent,
CPEX derives a session id from identity instead.

The session store is in-memory and per process. Labels reset when the proxy
restarts or hot-reloads.

## Request and response phases

- Request phase: after the full body is buffered, the filter dispatches the
  pre-invoke CMF hook for the route's entity. A deny becomes a rejection. On
  allow, delegated tokens are attached as upstream headers, and with
  `body_access: read_write` any mutated arguments are written back into the body.
- Response phase: the filter dispatches the post-invoke hook. `result.<field>`
  redactions run here, so a value the backend returns unsolicited is still
  stripped for a caller without the permission. A post-phase deny replaces the
  response body with a JSON-RPC error envelope.

The response status and headers are already committed by the time the body phase
runs, so a rewritten response body is fitted to the original Content-Length: it
is padded with trailing whitespace when shorter (JSON parsers ignore it), and a
rewrite that would grow the body fails closed to a length-fitting deny envelope
rather than desyncing HTTP framing.

## Decisions and denials

| Outcome | Wire shape |
|---|---|
| Identity / transport failure | HTTP 401, `WWW-Authenticate: Bearer`, `X-Cpex-Violation: <code>`. |
| Policy deny (PDP, predicate, PII, taint, delegation) | HTTP 200 with a JSON-RPC error envelope (`code -32001`), `X-Cpex-Violation: <code>`. Per the MCP Tools spec, gateway denials are JSON-RPC errors, not HTTP 4xx. |
| Missing `mcp.method` metadata | HTTP 500 (server-side misconfiguration). |

`X-Cpex-Violation` echoes the violation code (for example `apl.policy`,
`cedar.default_deny`, `pii.detected`, `session_tainted_secret`) so audit and
access-log pipelines can classify denials without parsing the body.

## Runtime requirements

The response phase drives async work with `block_in_place`, which requires a
multi-threaded tokio runtime. Run the proxy with `work_stealing: true`. On a
current-thread runtime the filter rejects every request with a clear error rather
than panicking mid-response.

## See also

- `examples/configs/security/cpex.yaml` for a runnable filter config.
- The CPEX HR demo in the [praxis-demos](https://github.com/praxis-proxy/demos) repository for an end-to-end walkthrough
  (identity, Cedar and CEL PDPs, delegation, redaction, PII scanning, session
  taint) with the Bob, Eve, and Alice personas.
