.PHONY: run test exercise

# The server writes its endpoint here on startup (its default, in the gitignored
# tsnet state dir); `make exercise` reads it. Override with APERTURE_ADDR_FILE.
ADDR_FILE ?= tsnet-state/addr

# Build and run the binary (not `go run`): interactive Ctrl-C is already safe
# since it signals the whole process group, but running the binary directly
# matches the integration runner and removes any go-run-orphan footgun if this
# is ever backgrounded and killed by PID.
run:
	go build -o aperture-mcp ./cmd/aperture-mcp && ./aperture-mcp

test:
	go test ./... && go vet ./...

# Drive a server started with `make run` end to end as a real MCP client,
# calling every tool and asserting allow/deny. Reads the server's address from
# $(ADDR_FILE) (override with ENDPOINT=...). Needs a client auth key tagged
# tag:aperture-client:
#   make exercise TS_AUTHKEY_CLIENT=tskey-auth-...
exercise:
	go run ./integration/client "$${ENDPOINT:-$$(cat $(ADDR_FILE))}"
