# 1. Identity is ambient, never client-asserted

Author: Guy J Grigsby
Status: Accepted

## Context

This MCP server authorizes tool calls by the caller's identity. An MCP server
can learn "who is calling" two ways:

1. **Client-asserted:** the caller passes an identity (user id, token, header,
   or a tool argument) and the server trusts or verifies it.
2. **Ambient:** the server derives identity from the transport itself, out of
   band from anything the caller can set.

The server runs over the tailnet via `tsnet`. Tailscale already authenticates
every node and exposes the peer behind a connection through `WhoIs`
(`UserProfile` for user nodes, tags for tagged nodes, plus a `CapMap` of ACL
grants). That makes a trustworthy ambient identity available for free.

An agent acting through this server is a confused-deputy risk: if identity were
a tool argument, a prompt-injected agent could simply claim to be an admin.

## Decision

Identity is **ambient**. It is resolved exclusively from `WhoIs` on the
connection's remote address. No tool accepts an identity/user/role parameter,
and no header or client-supplied value participates in authorization. The
authorization path **fails closed**: any error resolving identity or
capabilities yields a deny plus an audit line.

This invariant is enforced by a test: a tool call carrying a spoofed identity
argument produces the same decision as one without it.

## Consequences

- Transport is constrained to a network transport bound to the `tsnet`
  listener. Stdio (no network identity) is excluded.
- The server is only reachable on the tailnet. The tailnet is the perimeter, and
  authentication is delegated to Tailscale rather than reimplemented.
- A compromised or injected agent cannot escalate by asserting a different
  principal; it can only act with the grants of the identity it actually
  connects as.
- The `tsnet`/`WhoIs` mapping lives in an anti-corruption layer
  (`internal/tailnet`); the authorization domain stays free of vendor types.
- Trade-off: tighter coupling to Tailscale as the identity source. Acceptable,
  since identity-aware-over-tailnet is the explicit point of the project.
