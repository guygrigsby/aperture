# Identity-Aware MCP Server. Design

Author: Guy J Grigsby
Date: 2026-06-24
Status: Approved for implementation

## Why (the pitch, verbatim to reviewers)

> I chose this because it shows how I see the future of agentic oversight. The
> near-term problem with agents isn't capability, it's authorization and
> auditability. Ultimately, each tool call is made on behalf of a principal and
> should be gated by who that principal actually is. It is also particularly
> relevant to Aperture.

This take-home is an audition for the Aperture team, whose product is itself an
identity-aware LLM gateway. The deliverable is the smallest thing that proves
the central idea end to end, identity-aware RBAC wrapped around MCP, built to a
production bar in judgment rather than in volume.

## Scope

An MCP server that:

1. Serves over the tailnet via embedded `tsnet` (no public listener).
2. Identifies every caller from their Tailscale identity (`WhoIs` on the
   connection), never from anything the client asserts.
3. Authorizes each tool call against that identity's capability grants, sourced
   from the tailnet ACL (`CapMap`) with a local policy-file fallback so
   reviewers can run it without editing their ACL.
4. Emits a structured audit line per authorization decision.

The exposed tools are deliberately thin. They are the payload that makes the
authz boundary legible, not the substance:

- `whoami` echoes the resolved identity and granted capabilities.
- A small capability-gated resource store: `resource.list`, `resource.get`,
  `resource.put`. Each item declares a required capability; a reader identity
  sees public items, an admin identity sees and writes all.

## Non-Goals (chosen, not missed)

- No OS/exec/file tools. Shelling out invites RCE/sandbox concerns orthogonal to
  the point and would muddy the security story.
- No persistence beyond an in-memory store (resets on restart).
- No multi-node / HA, no rate limiting, no metrics backend, no grant caching.
  These are named in `PRODUCTION.md` as the path to production, not built.
- No stdio transport. It carries no network identity, so it cannot be
  identity-aware. HTTP/streamable transport bound to the `tsnet` listener only.

## Domain model (DDD)

Small, but the boundary discipline is the point. It demonstrates keeping vendor
types out of the domain, which is exactly the "agent-generated code that holds
the production bar" concern.

**Bounded context:** Authorization of MCP tool calls by tailnet identity.

**Ubiquitous language:**
- **Identity**: the resolved principal behind a connection (a user login, or a
  tagged node). Domain type, no Tailscale fields.
- **Capability**: a named permission string (e.g. `resource:read`,
  `resource:admin`).
- **Grant**: the set of capabilities an Identity holds.
- **Tool**: a callable, each declaring the Capability it requires.
- **Decision**: allow/deny + reason, the auditable output.

**Aggregate / invariant:** A `Decision` is produced only by evaluating a
required `Capability` against an `Identity`'s `Grant`. The invariant is **fail
closed**: any error resolving identity or capabilities yields *deny*.

**Anti-corruption layer:** `internal/tailnet` maps Tailscale's `WhoIs` result
(`UserProfile`, node tags, `CapMap`) into the domain `Identity` + `Grant`.
Tailscale types stop at this boundary; `internal/authz` imports nothing from
`tailscale.com`. A reviewer can verify with one grep.

## Architecture

```
cmd/aperture-mcp/main.go   composition root: load config, start tsnet, mount MCP, wire middleware
internal/authz/            DOMAIN: Identity, Capability, Grant, Tool, Decision; policy eval. No tailscale imports.
internal/tailnet/          ADAPTER: tsnet listener + WhoIs to domain Identity/Grant (anti-corruption layer)
internal/tools/            MCP tool surface (whoami + resource store), depends on authz
```

**Dependencies:** official `github.com/modelcontextprotocol/go-sdk` (version-
pinned), `tailscale.com` (tsnet). No third-party MCP SDK; this pins to the spec
source and compiles in CI so a hallucinated API can't survive.

**Verified transport mechanism (load-bearing):** the SDK's
`NewStreamableHTTPHandler(getServer func(*http.Request) *Server, opts)` returns
an `http.Handler`. We wrap it with our own middleware that calls
`WhoIs(req.RemoteAddr)` and injects the resolved domain `Identity`/`Grant` into
`req.Context()` *before* dispatch; tool handlers read identity from context.
Identity resolution therefore lives in our HTTP layer, not the SDK. That keeps
the authz core SDK-agnostic and the swap to a fallback SDK cheap if ever needed.

## Data flow (one tool call)

1. MCP client connects to the `tsnet` listener over the tailnet.
2. Server middleware resolves the caller: `tailnet.WhoIs(ctx, remoteAddr)` to a
   domain `Identity` + `Grant` (merged across all matching cap grants; local
   policy file consulted if `CapMap` has no entry).
3. Tool invoked, `authz.Decide(identity, grant, tool.Required)` returns a
   `Decision`.
4. Decision logged as one structured audit line (caller, tool, allow/deny,
   reason, capability).
5. Allow runs the tool. Deny returns an MCP error, no side effect.

## Authorization model

- **Primary:** Tailscale ACL *grants* with an app capability. `WhoIs` returns a
  `CapMap`; we read our capability key, parse the JSON rule array, and **merge**
  capabilities across all matching grants (not first-wins).
- **Fallback:** a `policy.json` mapping identity (login or tag) to capabilities,
  consulted only when no grant capability is present. Lets reviewers run the
  server and exercise allow/deny without touching their tailnet ACL.
- **User vs tagged nodes:** `WhoIs` yields a `UserProfile` for user nodes and
  tags for tagged nodes. Both are handled and mapped to `Identity`; conflating
  them is a common error we explicitly avoid.

## Security invariants (threat model summary; full version in PRODUCTION.md)

- **Ambient identity only.** Identity derives from the connection via `WhoIs`.
  No tool accepts a caller-supplied identity parameter. Enforced by test.
- **Fail closed.** Resolution/parse errors yield deny + audit line.
- **Tailnet perimeter.** Listener bound to the `tsnet` interface only, never
  `0.0.0.0`. No Funnel.
- **Secret hygiene.** `TS_AUTHKEY` from env; ephemeral node; tsnet state dir and
  any key material gitignored, never committed.

## Observability

`slog` (stdlib), one structured line per decision (caller, tool, capability,
allow/deny, reason). That is the observability story for an identity gateway: a
complete authorization audit trail. Plus a `/healthz` on the listener. No
Prometheus/OTel; named as future work.

## Error handling

- Sentinel `authz.ErrDenied`; errors wrapped with `%w`; `context` propagated and
  honored throughout.
- Every authz-path error resolves to deny, not a leak or a panic.

## Testing strategy

Bug-first / boundary-first. The credibility anchor is a single test that proves
the security boundary:

- **Deny path (written first):** an identity lacking `resource:admin` is denied
  the admin tool. Watch it pass for the right reason.
- **Allow path:** an admin identity is allowed.
- **Fallback:** identity with no `CapMap` entry resolves via `policy.json`.
- **Ambient-identity:** a tool call carrying a spoofed identity param does not
  change the decision.
- Table-driven, stdlib `testing` only. No mocks of the security logic itself.
  The domain is pure and tested directly; the tailnet adapter is tested with a
  fake `WhoIs` result.

`go test ./...` and `go vet ./...` run in CI.

## Repo deliverables

Code (~350-450 LOC incl. tests), plus exactly:

- `README.md`: the 2-3 sentence why, run/test instructions, and a short "Built
  with agents" section. My point of view on where coding agents accelerate vs.
  fail, and the public plugins I used to discipline them.
- `PRODUCTION.md`: honest demo-vs-prod gap list + threat model (grant caching,
  revocation latency, rate limiting, persistence, multi-node, metrics, and why I
  stopped where I did).
- `CLAUDE.md`: the agent steering file. Anti-slop rules, the DDD dependency rule
  (`internal/authz` imports no Tailscale), the ambient-identity invariant, test
  discipline. This file demonstrates deliberate agent control.
- `docs/adr/0001-identity-is-ambient.md`: the central security decision,
  recorded as an ADR.
- `Makefile`: `make run`, `make test`.
- `.github/workflows/ci.yml`: `go test ./... && go vet ./...`.
- `policy.example.json`: sample fallback policy for local testing.

## Agentic-development practices on display

The repo is itself the answer to the interview's core question (where agents
accelerate, where they fail, how you wrap them in review/test/security):

- **Discrete, scoped commits** narrating TDD red→green. History as process
  evidence, not one blob commit.
- **DDD boundary** verifiable by grep. Vendor types contained.
- **Pinned official SDK** compiled in CI. Hallucinated APIs can't survive.
- **Deny-path test written first.** Security boundary proven, not asserted.
- **`CLAUDE.md` anti-slop rules.** Deliberate steering, not spray-and-pray.
- **`PRODUCTION.md` gap list.** Naming the long tail is the senior signal under
  a time box; building all of it would signal the opposite.

## Amateur pitfalls explicitly avoided

Domain-specific:
- Client-asserted identity (we use ambient `WhoIs`).
- Binding `0.0.0.0` instead of the tsnet listener.
- Conflating user vs tagged nodes.
- First-grant-wins instead of merging capabilities.
- Committing auth keys / tsnet state.

Generic agentic-slop:
- Hallucinated SDK APIs (pinned + CI-compiled).
- Blob "implement everything" commit (discrete commits).
- Tests that test the mock / fail open (pure-domain tests, deny-first).
- Duplicated literals / wrong-layer logic (self-review pass).
