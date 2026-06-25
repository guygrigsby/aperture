# Production notes

What it takes to run this and what stands between the demo and a dependable
service. Honest about both.

## Runbook

Failure modes, all observed while building and testing this.

- **`TS_AUTHKEY` missing.** Server exits 1 with `TS_AUTHKEY is required`. Set a
  tagged ephemeral auth key.
- **Auth key rejected** (`tsnet.Up: backend: invalid key`). The key is expired,
  revoked, or single-use and already consumed. Mint a fresh reusable ephemeral
  key. Note: a Tailscale *API token* (`tskey-api-`) is not an auth key and will
  not register a node.
- **Node comes up untagged** with `APERTURE_REQUIRE_TAG` set: startup guardrail
  refuses to serve (`node is not tagged ...`). The auth key has no tag; mint it
  with the tag attached, and confirm `tagOwners` in your ACL permits it.
- **`WhoIs` fails for a caller.** The server logs a warning, binds an empty
  principal, and every tool denies (fail closed). Look for
  `whois failed, binding empty principal`.
- **Malformed cap grant.** `ProjectWhoIs` errors, the server binds an empty
  principal and denies (fail closed), logging `cap grant parse failed`. It does
  not fall through to the policy file.
- **No `policy.json` and no cap grant.** Every caller has an empty grant and is
  denied. Expected; add a grant or a policy.
- **Applying the ACL stanza.** The Tailscale policy API replaces the *entire*
  file. Add the `tagOwners`/`grants` keys to your existing policy; do not paste
  the integration stanza as your whole policy, or your devices lose
  connectivity. Keep a versioned backup of your policy first.

## Path to production

Deliberately not built, in rough priority order:

- **Grant caching and revocation latency.** `WhoIs` runs once per session with
  no cache. A revoked grant takes effect on the next session, not mid-session.
  Production wants a short-TTL cache plus a revocation signal.
- **Audit log to a sink.** Lines go to stdout. Production ships them to a store
  you can query and alert on; that is the point of "auditability."
- **Rate limiting** per identity, to bound abuse and `WhoIs` load.
- **Persistence.** The resource store is in-memory and resets on restart.
- **Multi-node / HA.** One process today. Multiple nodes need consistent
  identity resolution and shared state.
- **Metrics and tracing** beyond the audit log.
- **Resource-key enumeration.** A denied `resource.get` returns a generic
  `denied`, but a missing key returns `no such item "<key>"`, which names the key
  back. So an unauthorized caller can distinguish exists-but-denied from absent
  (their required capability is no longer disclosed, but existence is). Closing
  this needs a base capability to use the store at all, plus an
  indistinguishable not-found path; out of scope for the demo.
- **ACL boxing assumes a restrictive base policy.** On a default-allow tailnet
  the test tags inherit allow-all egress; the containment then comes only from
  ephemerality and the listener-only code, not the ACL.

## Threat model

- **Ambient identity.** Resolved only from `WhoIs` on the connection. No tool
  accepts a caller-supplied identity; nothing a client sends can change the
  authorization. Enforced by `TestSpoofedIdentityArgumentIgnored`. See
  `docs/adr/0001-identity-is-ambient.md`.
- **Fail closed.** Any error resolving identity or capabilities yields a deny
  plus an audit line. No fail-open, no panic on the authz path.
- **Tailnet perimeter.** The server binds only to the `tsnet` listener, never
  `0.0.0.0`, and uses no Funnel. Authentication is delegated to Tailscale.
- **Startup guardrail.** With `APERTURE_REQUIRE_TAG`, the server refuses to run
  unless it came up with the expected tag, catching a too-privileged key before
  the first request.
- **Secret hygiene.** `TS_AUTHKEY` from env; tsnet state and key material are
  gitignored and never committed.
