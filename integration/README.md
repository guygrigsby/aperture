# Integration test (least-privilege)

Drives the real tailnet path: a client calls the server over the tailnet and the
server authorizes by the caller's Tailscale identity. Opt-in and sandboxed so it
cannot touch anything but itself.

## For reviewers

You do not need this to evaluate the code. The authorization logic is covered by
unit tests with no setup:

```sh
make test
```

The steps below are only if you want to watch the real `tsnet` + `WhoIs` path on
**your own tailnet**. It needs tailnet admin access to add two tags and one
grant, runs entirely on disposable ACL-boxed nodes that are removed on exit, and
never runs from `make test` or CI.

## Why it is built this way

The unit tests cover the authorization logic with fakes. This test proves the
real `tsnet` + `WhoIs` path. Joining a tailnet is privileged, so the design
drives blast radius to near zero:

- **Two ephemeral, tagged nodes**, never a user identity: server is
  `tag:aperture-mcp`, client is `tag:aperture-client`. Both auto-remove on exit.
- **One ACL grant** (`acl.hujson`): client to server, port 80 only, read-only
  cap. The server tag gets no egress, so it can reach nothing on the tailnet.
- **Scoped keys**: ephemeral, tagged, ideally single-use. A leaked key mints
  only a boxed node, not a user.
- **Startup guardrail**: the server refuses to serve unless it actually came up
  tagged `tag:aperture-mcp` (`APERTURE_REQUIRE_TAG`), so a too-privileged key is
  caught before the first request. The client enforces the same on its side.
- **Opt-in**: gated behind `APERTURE_INTEGRATION=1`; never in `make test` or CI.

## Setup (once)

1. Apply `acl.hujson` to your tailnet policy (Admin console > Access controls).
2. Mint two ephemeral auth keys (Settings > Keys > Generate auth key):
   - one tagged `tag:aperture-mcp`   -> export as `TS_AUTHKEY`
   - one tagged `tag:aperture-client` -> export as `TS_AUTHKEY_CLIENT`
   Tick **Ephemeral**. Reusable is fine for iteration; single-use is stricter.

## Run

```sh
APERTURE_INTEGRATION=1 TS_AUTHKEY=... TS_AUTHKEY_CLIENT=... ./integration/run.sh
```

Expected: `whoami` reports `tag:aperture-client [resource:read]`,
`resource.get motd` is allowed, `resource.get secret` is **denied**, and the
server prints one structured `authz` audit line per decision. The admin/write
path is not exercised live by design; it is covered by the unit tests.

## Teardown

Nodes are ephemeral and disappear on exit. Revoke the auth keys after use; remove
the tags from your policy if you do not plan to re-run.
