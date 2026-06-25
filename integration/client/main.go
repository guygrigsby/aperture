// Command client is the integration-test MCP client. It joins the tailnet as
// its own ephemeral, tagged node (tag:aperture-client) and calls the
// aperture-mcp server over the tailnet, so the server's WhoIs resolves the
// caller as that tag. Least-privilege by construction: a disposable tagged
// node that the ACL boxes to reaching only the server on :80.
//
// It is a real test: it asserts the expected allow/deny outcomes and exits
// non-zero on any mismatch (while still printing responses for debugging).
//
// Usage:
//
//	TS_AUTHKEY_CLIENT=tskey-auth-... go run ./integration/client http://<server-ip>:80
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"tailscale.com/tsnet"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: client <server-endpoint>  (e.g. http://100.x.y.z:80)")
	}
	endpoint := os.Args[1]
	authKey := os.Getenv("TS_AUTHKEY_CLIENT")
	if authKey == "" {
		log.Fatal("TS_AUTHKEY_CLIENT is required (ephemeral key tagged tag:aperture-client)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	ts := &tsnet.Server{Hostname: "aperture-client", Dir: "tsnet-client-state", AuthKey: authKey, Ephemeral: true}
	defer ts.Close()
	status, err := ts.Up(ctx)
	if err != nil {
		log.Fatalf("tsnet up: %v", err)
	}
	// Mirror the server's PoLP guardrail: refuse to run if we did not come up
	// tagged as expected (i.e. a too-privileged key was used).
	if status.Self == nil || status.Self.Tags == nil || !slices.Contains(status.Self.Tags.AsSlice(), "tag:aperture-client") {
		log.Fatal("guardrail: client node is not tagged tag:aperture-client; refusing to run with a more-privileged identity")
	}

	c := mcp.NewClient(&mcp.Implementation{Name: "aperture-integration-client", Version: "0.1.0"}, nil)
	sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: ts.HTTPClient()}, nil)
	if err != nil {
		log.Fatalf("connect %s: %v", endpoint, err)
	}
	defer sess.Close()

	call := func(name string, args any) (isErr bool, text string) {
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			return true, "transport error: " + err.Error()
		}
		var sb strings.Builder
		for _, content := range res.Content {
			if tc, ok := content.(*mcp.TextContent); ok {
				sb.WriteString(tc.Text)
			}
		}
		return res.IsError, sb.String()
	}

	failed := false
	check := func(name string, ok, isErr bool, text string) {
		result := "PASS"
		if !ok {
			result = "FAIL"
			failed = true
		}
		fmt.Printf("[%s] %s  (isError=%v) %s\n", result, name, isErr, text)
	}

	// read-only tag:aperture-client: introspect, list, allowed read, denied read.
	isErr, txt := call("whoami", struct{}{})
	check("whoami resolves tag:aperture-client with resource:read",
		!isErr && strings.Contains(txt, "aperture-client") && strings.Contains(txt, "resource:read"), isErr, txt)

	isErr, txt = call("resource.list", struct{}{})
	check("list shows motd and not secret",
		!isErr && strings.Contains(txt, "motd") && !strings.Contains(txt, "secret"), isErr, txt)

	isErr, txt = call("resource.get", map[string]string{"key": "motd"})
	check("get motd allowed", !isErr && strings.Contains(txt, "hello tailnet"), isErr, txt)

	isErr, txt = call("resource.get", map[string]string{"key": "secret"})
	check("get secret denied", isErr, isErr, txt)

	if failed {
		fmt.Println("integration assertions FAILED")
		os.Exit(1)
	}
	fmt.Println("integration assertions passed")
}
