#!/usr/bin/env bash
# Opt-in, least-privilege integration test for aperture-mcp.
#
# Brings up the server and a tagged client as two ephemeral, ACL-boxed tailnet
# nodes, exercises one allow and one deny, and prints the server's audit lines.
# Never runs from `make test` or CI: it is gated behind APERTURE_INTEGRATION=1
# and requires two scoped, tagged, ephemeral auth keys.
#
# Prerequisites (see integration/README.md):
#   - integration/acl.hujson applied to your tailnet policy
#   - TS_AUTHKEY        : ephemeral key tagged tag:aperture-mcp
#   - TS_AUTHKEY_CLIENT : ephemeral key tagged tag:aperture-client
#
# Usage:
#   APERTURE_INTEGRATION=1 TS_AUTHKEY=... TS_AUTHKEY_CLIENT=... integration/run.sh
set -euo pipefail

if [[ "${APERTURE_INTEGRATION:-}" != "1" ]]; then
  echo "refusing to run: set APERTURE_INTEGRATION=1 to opt in (this joins your tailnet)" >&2
  exit 1
fi
: "${TS_AUTHKEY:?ephemeral key tagged tag:aperture-mcp}"
: "${TS_AUTHKEY_CLIENT:?ephemeral key tagged tag:aperture-client}"

cd "$(dirname "$0")/.."   # repo root (module dir)
work="$(mktemp -d)"
srvlog="$work/server.log"
addrfile="$work/addr"   # the server writes its endpoint here; no log scraping

# shellcheck disable=SC2329  # invoked indirectly via trap
cleanup() {
  [[ -n "${srvpid:-}" ]] && kill "$srvpid" 2>/dev/null || true
  rm -rf "$work" tsnet-state tsnet-client-state
}
trap cleanup EXIT

echo "starting server (tag:aperture-mcp, guardrail on)..."
# Build then run the binary directly. `go run` execs a child binary that does
# NOT die when the go-run parent is killed, which would orphan the server and
# leave its ephemeral tailnet node online. Running the binary means the cleanup
# trap kills the real process, so the node disconnects and auto-removes.
go build -o "$work/aperture-mcp" ./cmd/aperture-mcp
# Server fails closed if it does not come up tagged tag:aperture-mcp.
# APERTURE_POLICY points at an absent path so a stray local policy.json cannot
# affect the test: the run is cap-grant-only and hermetic.
APERTURE_REQUIRE_TAG=tag:aperture-mcp TS_HOSTNAME=aperture-mcp \
  APERTURE_POLICY="$work/no-such-policy.json" \
  APERTURE_ADDR_FILE="$addrfile" \
  "$work/aperture-mcp" >"$srvlog" 2>&1 &
srvpid=$!

echo "waiting for server to register and serve..."
ip=""
for _ in $(seq 1 60); do
  if ! kill -0 "$srvpid" 2>/dev/null; then echo "server exited early:" >&2; cat "$srvlog" >&2; exit 1; fi
  [[ -f "$addrfile" ]] && { ip="$(cat "$addrfile")"; break; }
  sleep 1
done
[[ -z "$ip" ]] && { echo "server never wrote its address:" >&2; cat "$srvlog" >&2; exit 1; }
echo "server up at $ip"

echo "running client (tag:aperture-client)..."
client_rc=0
go run ./integration/client "$ip" || client_rc=$?

echo
echo "=== server audit lines (authz decisions) ==="
grep '"msg":"authz"' "$srvlog" || echo "(none captured)"

# Propagate the client's verdict so the harness behaves like a real test.
exit "$client_rc"
