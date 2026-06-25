# aperture-mcp

Identity-aware MCP server. It serves over the tailnet, identifies every caller
from their Tailscale identity (`WhoIs` on the connection, never client-asserted),
and authorizes each tool call against that identity's capability grants. One
structured audit line per decision.

A working miniature of the concern behind Tailscale's Aperture: identity-aware
access control wrapped around MCP.

## Why

> I chose this because it shows how I see the future of agentic oversight. The
> near-term problem with agents isn't capability, it's authorization and
> auditability. Ultimately, each tool call is made on behalf of a principal and
> should be gated by who that principal actually is. It is also particularly
> relevant to Aperture.

## How it works

The server embeds `tsnet`, so it only listens on the tailnet. For each session
it resolves the caller once from `WhoIs(remoteAddr)` and binds the tools to that
principal, so no tool can accept a caller-supplied identity (ambient identity,
see `docs/adr/0001-identity-is-ambient.md`). Each tool authorizes through a pure
domain core (`internal/authz`) that imports nothing from Tailscale; vendor types
stop at the adapter (`internal/tailnet`). Design: `docs/specs/`.

## Run

Needs a Tailscale auth key (tagged, ephemeral, reusable is convenient):

```sh
export TS_AUTHKEY=tskey-auth-...      # required
make run                              # go run ./cmd/aperture-mcp
```

Authorization comes from tailnet capability grants (the app cap
`grigsby.dev/cap/aperture-mcp` in your ACL). For local testing without ACL
edits, drop in the fallback policy:

```sh
cp policy.example.json policy.json    # edit to map your login/tag to caps
```

Optional env: `TS_HOSTNAME` (default `aperture-mcp`), `APERTURE_POLICY` (default
`policy.json`), `APERTURE_REQUIRE_TAG` (refuse to serve unless the node came up
with this tag). Connect any MCP client over the tailnet at
`http://aperture-mcp:80`. Tools: `whoami`, `resource.list`, `resource.get`,
`resource.put`.

## Test

The authorization logic is covered by unit tests, no setup:

```sh
make test            # go test ./... && go vet ./...
```

To watch the real `tsnet` + `WhoIs` path live on your own tailnet, see
`integration/README.md` (opt-in, sandboxed, runs on disposable tagged nodes).

## Plug it into your agent

The server speaks MCP over streamable HTTP on the tailnet, so any MCP client on
the same tailnet can use it. The client's own Tailscale identity is what gets
authorized, so give that identity a cap grant (or a `policy.json` entry).

Claude Code:

```sh
claude mcp add --transport http aperture http://aperture-mcp:80
```

Or in an MCP client config:

```json
{ "mcpServers": { "aperture": { "url": "http://aperture-mcp:80" } } }
```

The agent then has `whoami`, `resource.list`, `resource.get`, and `resource.put`,
each gated by the caller's tailnet identity. To drive a running server without an
AI client (calls every tool, asserts allow/deny), use `make exercise`.

## Audit log

One structured JSON line per authorization decision, with `tool` and
`capability` as separate fields so a log pipeline can filter on either. Captured
from a live run, a read-only `tag:aperture-client` calling the server (the
`time` field is trimmed below for width):

```json
{"level":"INFO","msg":"authz","caller":"tag:aperture-client","tool":"whoami","capability":"","decision":"allow","reason":"introspection"}
{"level":"INFO","msg":"authz","caller":"tag:aperture-client","tool":"resource.list","capability":"","decision":"filter","reason":"1 of 2 visible"}
{"level":"INFO","msg":"authz","caller":"tag:aperture-client","tool":"resource.get","capability":"resource:read","decision":"allow","reason":"granted"}
{"level":"INFO","msg":"authz","caller":"tag:aperture-client","tool":"resource.get","capability":"resource:admin","decision":"deny","reason":"tag:aperture-client lacks resource:admin"}
```

The denial reason lives only in the audit log. The client gets a generic
`denied`, no value and no capability disclosure.

## Built with agents

This was built with Claude Code, and the repo is partly an answer to how I wrap
agents so their output holds a production bar.

Where agents helped: scaffolding the whole thing fast once the MCP SDK surface
was pinned. The first task was a spike that read the real SDK API with `go doc`
before any code leaned on it, so a hallucinated signature could not survive.

Where they failed, and how it got caught:

- An unanchored `.gitignore` pattern silently dropped the entire `cmd/`
  directory from git. Everything built locally, so nothing looked wrong. A
  fresh-clone build check caught it. Lesson: verify the shipped artifact, not
  the working tree.
- A review agent flagged `go 1.26` as "not a real version" (its training
  predates it) and the suggested fix broke the build. The build caught it.
  Agent reviews need their own verification; do not apply them blind.
- A separate agent reviewed the security core and found four real issues
  (`whoami` not failing closed, a malformed cap grant falling open, the missing
  spoofed-identity test, an unaudited list path). All fixed, each with a test.

The discipline that made that work: TDD with the deny path written first,
discrete commits, a pinned SDK compiled in CI, and an adversarial review pass
whose findings I verified rather than trusted.

## More

- Operating it and the path to production: `PRODUCTION.md`
- Why identity is ambient: `docs/adr/0001-identity-is-ambient.md`
- Live integration test: `integration/README.md`
