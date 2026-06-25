# Identity-Aware MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An MCP server that serves over the tailnet, identifies callers by their Tailscale identity, and authorizes every tool call against that identity's capability grants, with a structured audit line per decision.

**Architecture:** A pure domain core (`internal/authz`) decides allow/deny from an `Identity` + `Grant` + required `Capability`. An anti-corruption layer (`internal/tailnet`) maps Tailscale `WhoIs` results into domain types. HTTP middleware resolves identity per request and injects it into context before the MCP SDK dispatches to a tool. Tools (`internal/tools`) read identity from context and call `authz.Decide`. The domain imports nothing from `tailscale.com`.

**Tech Stack:** Go, `github.com/modelcontextprotocol/go-sdk` (official MCP SDK, version-pinned), `tailscale.com` (tsnet), stdlib `slog` / `testing` / `net/http`.

## Global Constraints

- **Identity is ambient.** Resolved only from `WhoIs` on the connection. No tool accepts an `identity`/`user`/`role` argument. (`docs/adr/0001-identity-is-ambient.md`)
- **Fail closed.** Any error resolving identity or capabilities yields *deny* + an audit line. No fail-open, no panic on the authz path.
- **DDD dependency rule.** `internal/authz` imports nothing from `tailscale.com`. Verifiable with one grep.
- **Tailnet perimeter.** Bind only to the `tsnet` listener, never `0.0.0.0`. No Funnel. `TS_AUTHKEY` from env; tsnet state + keys gitignored.
- **No em/en dashes** anywhere (code comments, docs, commit messages). Terse, verb-first.
- **No agent attribution in git.** No `Co-Authored-By`, no "Generated with" footers.
- **Progressive disclosure.** Docs: README (what + run) links to PRODUCTION.md (operate + harden) links to ADR (why). MCP `instructions` and tool descriptions stay terse; detail surfaces on demand via tool output.
- **Doc size cap.** README and PRODUCTION.md each fit roughly one screen. Real content only; no invented failure modes, no padding.
- **Module path:** `github.com/guygrigsby/aperture-mcp` (adjust if repo path differs).

---

## File Structure

```
go.mod, go.sum
cmd/aperture-mcp/main.go          composition root: config, tsnet, handler, middleware, tools, /healthz
internal/authz/authz.go           DOMAIN: Identity, Capability, Grant, Tool, Decision, ErrDenied, Decide
internal/authz/authz_test.go      deny-first boundary tests (the credibility anchor)
internal/authz/policy.go          policy.json loader -> identity->capabilities fallback
internal/authz/policy_test.go     loader test with fixture
internal/tailnet/identity.go      ADAPTER: WhoIs result -> domain Identity/Grant (merge caps, user vs tagged)
internal/tailnet/identity_test.go adapter test with fake WhoIs results
internal/tailnet/middleware.go    HTTP middleware: resolve identity, inject into context, audit log
internal/tailnet/middleware_test.go middleware test with httptest + fake resolver
internal/tools/tools.go           whoami + resource store, gated via authz
internal/tools/tools_test.go      ambient-identity test (spoofed arg ignored), allow/deny via tools
Makefile                          run, test
.github/workflows/ci.yml          go test ./... && go vet ./...
policy.example.json               sample fallback policy
.gitignore                        add tsnet state dir, *.authkey
README.md                         why + verified run/test + audit-log sample + Built with agents
PRODUCTION.md                     runbook + path to production + threat model
```

**Honesty note on the SDK (read before Task 2):** the SDK's HTTP handler signature is verified (`NewStreamableHTTPHandler(getServer func(*http.Request) *Server, opts) *StreamableHTTPHandler`, implements `http.Handler`). The exact **tool-registration** API and whether `req.Context()` propagates into a tool handler's `ctx` are **not** yet verified. **Task 1 is a spike that pins these.** Tasks 6 and 7 show the intended shape; where the spike's findings differ, the spike is authoritative and the code is adjusted to the real signatures. This is deliberate: it is the "pin the SDK, let CI catch hallucinated APIs" discipline in practice.

---

### Task 1: Module + dependencies + SDK/tsnet spike

**Files:**
- Create: `go.mod`, `cmd/aperture-mcp/main.go` (temporary spike form)
- Create: `.gitignore` additions

**Interfaces:**
- Produces: verified facts for later tasks: (a) exact `mcp.NewServer` + tool-registration call, (b) the tool-handler function signature, (c) whether `req.Context()` reaches the handler `ctx` (decides whether middleware-via-context works, or we bind identity per request via the `getServer` callback).

- [ ] **Step 1: Init module and add deps**

```bash
go mod init github.com/guygrigsby/aperture-mcp
go get github.com/modelcontextprotocol/go-sdk/mcp@latest
go get tailscale.com/tsnet@latest
```

- [ ] **Step 2: Add gitignore entries**

Append to `.gitignore`:
```
/tsnet-state/
*.authkey
aperture-mcp
```

- [ ] **Step 3: Write a minimal spike `main.go`**

Goal: one trivial `echo` tool served over StreamableHTTP on a tsnet listener, plus a log line inside the tool handler printing whatever it can read from `ctx` and the request. Use it to answer the three verification questions. Intended shape (adjust to real API):

```go
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"tailscale.com/tsnet"
)

type echoIn struct {
	Text string `json:"text"`
}

func main() {
	s := &tsnet.Server{Hostname: "aperture-mcp-spike", Dir: "tsnet-state"}
	defer s.Close()
	ln, err := s.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}

	srv := mcp.NewServer(&mcp.Implementation{Name: "aperture-mcp", Version: "0.0.1"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "echo", Description: "echo text"},
		func(ctx context.Context, req *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
			log.Printf("handler ctx value test: %v", ctx.Value(ctxKey{}))
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Text}}}, nil, nil
		})

	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	wrapped := func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, "from-middleware"))
		h.ServeHTTP(w, r)
	}
	log.Fatal(http.Serve(ln, http.HandlerFunc(wrapped)))
}

type ctxKey struct{}
```

- [ ] **Step 4: Build and verify**

Run: `go build ./... && go vet ./...`
Expected: compiles clean. If a symbol is wrong (`NewServer`, `AddTool`, `CallToolResult`, `TextContent`), fix to the real names from `go doc github.com/modelcontextprotocol/go-sdk/mcp` and record the corrections at the top of the plan's Task 6/7 notes.

- [ ] **Step 5: Record the three verified facts as code comments in main.go**

Note in comments: the real registration call, the real handler signature, and whether the "from-middleware" value reached the handler (`ctx.Value` printed it) or not. This decides Task 5's approach.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum .gitignore cmd/
git commit -m "spike: tsnet listener + MCP StreamableHTTP, pin SDK API"
```

---

### Task 2: Domain core, deny-first (`internal/authz`)

**Files:**
- Create: `internal/authz/authz.go`, `internal/authz/authz_test.go`

**Interfaces:**
- Produces:
  - `type Capability string`
  - `type Identity struct { Kind IdentityKind; Name string }` where `IdentityKind` is `KindUser` or `KindTagged`
  - `type Grant struct { Caps map[Capability]bool }`; method `Has(Capability) bool`
  - `type Tool struct { Name string; Required Capability }`
  - `type Decision struct { Allow bool; Reason string; Capability Capability }`
  - `var ErrDenied = errors.New("denied")`
  - `func Decide(id Identity, g Grant, required Capability) Decision`

- [ ] **Step 1: Write the failing test (deny path first)**

```go
package authz

import "testing"

func TestDecide(t *testing.T) {
	reader := Identity{Kind: KindUser, Name: "reader@example.com"}
	admin := Identity{Kind: KindUser, Name: "admin@example.com"}
	readerGrant := Grant{Caps: map[Capability]bool{"resource:read": true}}
	adminGrant := Grant{Caps: map[Capability]bool{"resource:read": true, "resource:admin": true}}

	tests := []struct {
		name     string
		id       Identity
		grant    Grant
		required Capability
		want     bool
	}{
		{"reader denied admin", reader, readerGrant, "resource:admin", false},
		{"admin allowed admin", admin, adminGrant, "resource:admin", true},
		{"reader allowed read", reader, readerGrant, "resource:read", true},
		{"empty grant denied", reader, Grant{}, "resource:read", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(tc.id, tc.grant, tc.required)
			if got.Allow != tc.want {
				t.Fatalf("Decide allow = %v, want %v (reason: %q)", got.Allow, tc.want, got.Reason)
			}
			if !got.Allow && got.Reason == "" {
				t.Fatal("deny must carry a reason for the audit line")
			}
		})
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/authz/ -run TestDecide -v`
Expected: FAIL, `undefined: Decide` (and the types).

- [ ] **Step 3: Implement minimal `authz.go`**

```go
// Package authz is the authorization domain. It imports nothing from
// tailscale.com; vendor types stop at internal/tailnet.
package authz

import (
	"errors"
	"fmt"
)

var ErrDenied = errors.New("denied")

type Capability string

type IdentityKind int

const (
	KindUser IdentityKind = iota
	KindTagged
)

type Identity struct {
	Kind IdentityKind
	Name string // user login, or tag name
}

func (i Identity) String() string {
	if i.Kind == KindTagged {
		return "tag:" + i.Name
	}
	return i.Name
}

type Grant struct {
	Caps map[Capability]bool
}

func (g Grant) Has(c Capability) bool { return g.Caps[c] }

type Tool struct {
	Name     string
	Required Capability
}

type Decision struct {
	Allow      bool
	Reason     string
	Capability Capability
}

// Decide is the only place an allow/deny is produced. Fail closed: an empty
// grant or a missing capability is a deny with a reason for the audit line.
func Decide(id Identity, g Grant, required Capability) Decision {
	if g.Has(required) {
		return Decision{Allow: true, Reason: "granted", Capability: required}
	}
	return Decision{
		Allow:      false,
		Reason:     fmt.Sprintf("%s lacks %s", id, required),
		Capability: required,
	}
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `go test ./internal/authz/ -run TestDecide -v`
Expected: PASS, all four subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/authz/
git commit -m "authz: domain Decide, deny-first tests (the security boundary)"
```

---

### Task 3: Policy fallback loader (`internal/authz`)

**Files:**
- Create: `internal/authz/policy.go`, `internal/authz/policy_test.go`, test fixture inline

**Interfaces:**
- Consumes: `Capability`, `Grant`, `Identity` from Task 2.
- Produces:
  - `type Policy struct { ... }`
  - `func LoadPolicy(path string) (*Policy, error)`
  - `func (p *Policy) GrantFor(id Identity) Grant` (empty Grant if no match, never nil map deref)

- [ ] **Step 1: Write the failing test**

```go
package authz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyGrantFor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	const doc = `{
	  "users": { "admin@example.com": ["resource:read", "resource:admin"],
	             "reader@example.com": ["resource:read"] },
	  "tags":  { "ci": ["resource:read"] }
	}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if !p.GrantFor(Identity{Kind: KindUser, Name: "admin@example.com"}).Has("resource:admin") {
		t.Fatal("admin should have resource:admin from policy")
	}
	if p.GrantFor(Identity{Kind: KindUser, Name: "reader@example.com"}).Has("resource:admin") {
		t.Fatal("reader should not have resource:admin")
	}
	if !p.GrantFor(Identity{Kind: KindTagged, Name: "ci"}).Has("resource:read") {
		t.Fatal("tag:ci should have resource:read")
	}
	if g := p.GrantFor(Identity{Kind: KindUser, Name: "nobody@example.com"}); len(g.Caps) != 0 {
		t.Fatal("unknown identity should get empty grant")
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/authz/ -run TestPolicyGrantFor -v`
Expected: FAIL, `undefined: LoadPolicy`.

- [ ] **Step 3: Implement `policy.go`**

```go
package authz

import (
	"encoding/json"
	"fmt"
	"os"
)

// Policy is the local fallback consulted when a caller has no capability grant
// in their tailnet CapMap. Lets reviewers exercise allow/deny without editing
// their tailnet ACL.
type Policy struct {
	Users map[string][]Capability `json:"users"`
	Tags  map[string][]Capability `json:"tags"`
}

func LoadPolicy(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}
	return &p, nil
}

func (p *Policy) GrantFor(id Identity) Grant {
	var caps []Capability
	switch id.Kind {
	case KindUser:
		caps = p.Users[id.Name]
	case KindTagged:
		caps = p.Tags[id.Name]
	}
	g := Grant{Caps: make(map[Capability]bool, len(caps))}
	for _, c := range caps {
		g.Caps[c] = true
	}
	return g
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `go test ./internal/authz/ -v`
Expected: PASS (TestDecide and TestPolicyGrantFor).

- [ ] **Step 5: Commit**

```bash
git add internal/authz/policy.go internal/authz/policy_test.go
git commit -m "authz: policy.json fallback loader"
```

---

### Task 4: Tailnet adapter (`internal/tailnet`)

**Files:**
- Create: `internal/tailnet/identity.go`, `internal/tailnet/identity_test.go`

**Interfaces:**
- Consumes: `authz.Identity`, `authz.Grant`, `authz.Capability`, `authz.Policy`.
- Produces:
  - `const CapName = "guygrigsby.dev/cap/aperture-mcp"` (the app capability key in the tailnet ACL)
  - `type WhoIsResult struct { LoginName string; Tags []string; Caps []authz.Capability }` (the already-extracted, vendor-free shape the adapter maps from; the real `tailscale.com/client/...WhoIs` extraction into this shape happens in main, keeping this package testable without a tailnet)
  - `func Resolve(w WhoIsResult, fallback *authz.Policy) (authz.Identity, authz.Grant)` (merges CapMap-derived caps; consults fallback only when `w.Caps` is empty; handles user vs tagged)

- [ ] **Step 1: Write the failing test**

```go
package tailnet

import (
	"testing"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
)

func TestResolve(t *testing.T) {
	pol := &authz.Policy{
		Users: map[string][]authz.Capability{"reader@example.com": {"resource:read"}},
	}

	// User node with caps from the tailnet grant: caps win, fallback not consulted.
	id, g := Resolve(WhoIsResult{LoginName: "admin@example.com", Caps: []authz.Capability{"resource:read", "resource:admin"}}, pol)
	if id.Kind != authz.KindUser || id.Name != "admin@example.com" {
		t.Fatalf("identity = %+v", id)
	}
	if !g.Has("resource:admin") {
		t.Fatal("grant caps should come from CapMap")
	}

	// User node with no caps: fallback policy supplies them.
	_, g = Resolve(WhoIsResult{LoginName: "reader@example.com"}, pol)
	if !g.Has("resource:read") || g.Has("resource:admin") {
		t.Fatal("fallback should grant read only")
	}

	// Tagged node maps to KindTagged using the first tag.
	id, _ = Resolve(WhoIsResult{Tags: []string{"tag:ci"}}, pol)
	if id.Kind != authz.KindTagged || id.Name != "ci" {
		t.Fatalf("tagged identity = %+v", id)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/tailnet/ -run TestResolve -v`
Expected: FAIL, `undefined: Resolve`.

- [ ] **Step 3: Implement `identity.go`**

```go
// Package tailnet is the anti-corruption layer. It maps Tailscale WhoIs data
// into the authz domain. The domain (internal/authz) imports nothing from
// tailscale.com; the raw WhoIs -> WhoIsResult extraction lives in main, this
// package maps WhoIsResult -> domain types and stays unit-testable.
package tailnet

import (
	"strings"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
)

// CapName is the app-capability key we read from the tailnet ACL grant CapMap.
const CapName = "guygrigsby.dev/cap/aperture-mcp"

// WhoIsResult is the vendor-free projection of a tailscale WhoIs lookup.
type WhoIsResult struct {
	LoginName string             // set for user nodes
	Tags      []string           // set for tagged nodes (e.g. "tag:ci")
	Caps      []authz.Capability // merged capabilities from the CapMap grant
}

// Resolve maps a WhoIsResult to a domain Identity and Grant. CapMap caps win;
// the fallback policy is consulted only when the node carries no caps.
func Resolve(w WhoIsResult, fallback *authz.Policy) (authz.Identity, authz.Grant) {
	var id authz.Identity
	switch {
	case len(w.Tags) > 0:
		id = authz.Identity{Kind: authz.KindTagged, Name: strings.TrimPrefix(w.Tags[0], "tag:")}
	default:
		id = authz.Identity{Kind: authz.KindUser, Name: w.LoginName}
	}

	if len(w.Caps) > 0 {
		g := authz.Grant{Caps: make(map[authz.Capability]bool, len(w.Caps))}
		for _, c := range w.Caps {
			g.Caps[c] = true
		}
		return id, g
	}
	if fallback != nil {
		return id, fallback.GrantFor(id)
	}
	return id, authz.Grant{}
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `go test ./internal/tailnet/ -run TestResolve -v`
Expected: PASS.

- [ ] **Step 5: Verify the DDD dependency rule holds**

Run: `go list -deps ./internal/authz/ | grep tailscale.com && echo VIOLATION || echo "clean: authz has no tailscale dep"`
Expected: `clean: authz has no tailscale dep`.

- [ ] **Step 6: Commit**

```bash
git add internal/tailnet/identity.go internal/tailnet/identity_test.go
git commit -m "tailnet: WhoIs -> domain identity/grant (anti-corruption layer)"
```

---

### Task 5: Identity middleware + context (`internal/tailnet`)

**Files:**
- Create: `internal/tailnet/middleware.go`, `internal/tailnet/middleware_test.go`

**Interfaces:**
- Consumes: `authz.Identity`, `authz.Grant`, `Resolve`.
- Produces:
  - `type Resolver func(remoteAddr string) (WhoIsResult, error)` (real impl in main calls tsnet `WhoIs`; tests pass a fake)
  - `type principal struct { ID authz.Identity; Grant authz.Grant }` (unexported; stashed in context)
  - `func Middleware(next http.Handler, r Resolver, fallback *authz.Policy, log *slog.Logger) http.Handler`
  - `func FromContext(ctx context.Context) (authz.Identity, authz.Grant, bool)`

**Branch on Task 1 finding:** this middleware-via-`req.Context()` design assumes the spike confirmed `req.Context()` reaches the tool handler `ctx`. If it does **not**, replace the context injection with per-request identity binding through the `getServer` callback (resolve in `getServer(*http.Request)`, build a server whose tools close over the principal). Keep `FromContext` semantics identical so Task 6 is unchanged.

- [ ] **Step 1: Write the failing test**

```go
package tailnet

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
)

func TestMiddlewareInjectsIdentity(t *testing.T) {
	fake := func(remoteAddr string) (WhoIsResult, error) {
		return WhoIsResult{LoginName: "admin@example.com", Caps: []authz.Capability{"resource:admin"}}, nil
	}
	var gotName string
	var gotOK bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _, ok := FromContext(r.Context())
		gotName, gotOK = id.Name, ok
	})
	h := Middleware(inner, fake, nil, slogDiscard())
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "100.64.0.1:1234"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !gotOK || gotName != "admin@example.com" {
		t.Fatalf("identity not injected: ok=%v name=%q", gotOK, gotName)
	}
}
```

(Add a tiny `slogDiscard()` helper returning `slog.New(slog.NewTextHandler(io.Discard, nil))`.)

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/tailnet/ -run TestMiddlewareInjectsIdentity -v`
Expected: FAIL, `undefined: Middleware`.

- [ ] **Step 3: Implement `middleware.go`**

```go
package tailnet

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
)

type Resolver func(remoteAddr string) (WhoIsResult, error)

type ctxKey struct{}

type principal struct {
	ID    authz.Identity
	Grant authz.Grant
}

// Middleware resolves the caller's tailnet identity and injects it into the
// request context before the MCP handler runs. Fail closed: a resolver error
// injects nothing, so downstream Decide calls see an empty grant and deny.
func Middleware(next http.Handler, r Resolver, fallback *authz.Policy, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		who, err := r(req.RemoteAddr)
		if err != nil {
			log.Warn("whois failed, request proceeds unauthenticated", "remote", req.RemoteAddr, "err", err)
			next.ServeHTTP(w, req) // no principal in context -> deny at tool
			return
		}
		id, grant := Resolve(who, fallback)
		ctx := context.WithValue(req.Context(), ctxKey{}, principal{ID: id, Grant: grant})
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

func FromContext(ctx context.Context) (authz.Identity, authz.Grant, bool) {
	p, ok := ctx.Value(ctxKey{}).(principal)
	if !ok {
		return authz.Identity{}, authz.Grant{}, false
	}
	return p.ID, p.Grant, true
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `go test ./internal/tailnet/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tailnet/middleware.go internal/tailnet/middleware_test.go
git commit -m "tailnet: identity middleware injects principal into request context"
```

---

### Task 6: Tools, gated by authz (`internal/tools`)

**Files:**
- Create: `internal/tools/tools.go`, `internal/tools/tools_test.go`

**Interfaces:**
- Consumes: `authz.Decide`, `authz.Tool`, `tailnet.FromContext`, the SDK registration call verified in Task 1.
- Produces: `func Register(srv *mcp.Server, store *Store, log *slog.Logger)`; `type Store` (in-memory resource store); a gate helper `authorize(ctx, log, required) (authz.Identity, error)` that calls `FromContext` + `Decide`, logs the audit line, returns `ErrDenied` on deny.

**Use the Task 1 facts** for the exact `mcp.AddTool` signature and result types. The gate logic below is SDK-agnostic and is the part under test.

- [ ] **Step 1: Write the failing test (ambient identity + allow/deny via the gate)**

```go
package tools

import (
	"context"
	"errors"
	"testing"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
	"github.com/guygrigsby/aperture-mcp/internal/tailnet"
)

func ctxWith(id authz.Identity, caps ...authz.Capability) context.Context {
	g := authz.Grant{Caps: map[authz.Capability]bool{}}
	for _, c := range caps {
		g.Caps[c] = true
	}
	return tailnet.NewTestContext(context.Background(), id, g)
}

func TestAuthorizeAmbientIdentity(t *testing.T) {
	admin := authz.Identity{Kind: authz.KindUser, Name: "admin@example.com"}
	reader := authz.Identity{Kind: authz.KindUser, Name: "reader@example.com"}

	// reader denied admin capability
	if _, err := authorize(ctxWith(reader, "resource:read"), slogDiscard(), "resource:admin"); !errors.Is(err, authz.ErrDenied) {
		t.Fatal("reader must be denied resource:admin")
	}
	// admin allowed
	if _, err := authorize(ctxWith(admin, "resource:read", "resource:admin"), slogDiscard(), "resource:admin"); err != nil {
		t.Fatalf("admin must be allowed: %v", err)
	}
	// no principal in context -> deny (ambient: nothing the caller passes can change this)
	if _, err := authorize(context.Background(), slogDiscard(), "resource:read"); !errors.Is(err, authz.ErrDenied) {
		t.Fatal("missing principal must deny")
	}
}
```

(Requires a `tailnet.NewTestContext` helper exported for tests, and a local `slogDiscard()`.)

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/tools/ -run TestAuthorizeAmbientIdentity -v`
Expected: FAIL, `undefined: authorize` (and `tailnet.NewTestContext`).

- [ ] **Step 3: Add `tailnet.NewTestContext` and implement the gate + tools**

Add to `internal/tailnet/middleware.go`:
```go
// NewTestContext injects a principal for tests in other packages.
func NewTestContext(ctx context.Context, id authz.Identity, g authz.Grant) context.Context {
	return context.WithValue(ctx, ctxKey{}, principal{ID: id, Grant: g})
}
```

`internal/tools/tools.go` (registration calls adjusted to Task 1's verified API):
```go
// Package tools exposes the MCP tool surface. Every tool authorizes through
// authz.Decide against the ambient identity in context; none accept a
// caller-supplied identity. Tool descriptions stay terse (progressive
// disclosure); detail surfaces in whoami output.
package tools

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
	"github.com/guygrigsby/aperture-mcp/internal/tailnet"
)

// authorize is the single gate. It reads the ambient identity, decides, emits
// the audit line, and returns ErrDenied on deny. SDK-agnostic on purpose.
func authorize(ctx context.Context, log *slog.Logger, required authz.Capability) (authz.Identity, error) {
	id, grant, ok := tailnet.FromContext(ctx)
	if !ok {
		log.Info("authz", "tool_cap", required, "decision", "deny", "reason", "no identity")
		return authz.Identity{}, fmt.Errorf("%w: no identity", authz.ErrDenied)
	}
	d := authz.Decide(id, grant, required)
	log.Info("authz", "caller", id.String(), "cap", required, "decision", map[bool]string{true: "allow", false: "deny"}[d.Allow], "reason", d.Reason)
	if !d.Allow {
		return id, fmt.Errorf("%w: %s", authz.ErrDenied, d.Reason)
	}
	return id, nil
}

// Store is a tiny in-memory resource store. Each item names the capability
// required to read it. ponytail: in-memory, resets on restart; persistence is
// a PRODUCTION.md gap, not needed to show the boundary.
type Store struct {
	mu    sync.RWMutex
	items map[string]Item
}

type Item struct {
	Key      string          `json:"key"`
	Value    string          `json:"value"`
	Required authz.Capability `json:"required"`
}

func NewStore() *Store {
	return &Store{items: map[string]Item{
		"motd":   {Key: "motd", Value: "hello tailnet", Required: "resource:read"},
		"secret": {Key: "secret", Value: "admin-only value", Required: "resource:admin"},
	}}
}
```

Then `Register` wires `whoami`, `resource.list`, `resource.get`, `resource.put` using the Task 1 registration call. Each handler calls `authorize(ctx, log, <required cap>)` first and returns the SDK error result on `ErrDenied`. `whoami` requires no capability beyond a present identity and returns `id.String()` + sorted caps.

- [ ] **Step 4: Run tests, verify pass**

Run: `go test ./internal/tools/ -v`
Expected: PASS.

- [ ] **Step 5: Build the whole module**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add internal/tools/ internal/tailnet/middleware.go
git commit -m "tools: whoami + capability-gated resource store, ambient-identity test"
```

---

### Task 7: Composition root (`cmd/aperture-mcp/main.go`)

**Files:**
- Modify: `cmd/aperture-mcp/main.go` (replace the spike with the real wiring)
- Create: `policy.example.json`

**Interfaces:**
- Consumes: everything above + tsnet `WhoIs`. Builds the real `tailnet.Resolver` that calls `tsnet.Server.LocalClient().WhoIs` and projects the result into `tailnet.WhoIsResult` (extract `LoginName` from `UserProfile`, `Tags` from the node, caps from `CapMap[tailnet.CapName]`).

- [ ] **Step 1: Replace main.go with real wiring**

Config from env: `TS_AUTHKEY` (required), `TS_HOSTNAME` (default `aperture-mcp`), `APERTURE_POLICY` (default `policy.json`, optional). Start tsnet, load policy if present, build resolver, build MCP server + tools, wrap handler in `tailnet.Middleware`, add `/healthz`, serve on the tsnet listener. Full code written here against the Task 1 verified API and the real `LocalClient().WhoIs` signature (`(*apitype.WhoIsResponse, error)`); project `WhoIsResponse.UserProfile.LoginName`, `WhoIsResponse.Node.Tags`, and `WhoIsResponse.CapMap[CapName]` (unmarshal each raw cap rule, collect capability strings, merge).

- [ ] **Step 2: Write `policy.example.json`**

```json
{
  "users": {
    "you@example.com": ["resource:read", "resource:admin"],
    "teammate@example.com": ["resource:read"]
  },
  "tags": {
    "ci": ["resource:read"]
  }
}
```

- [ ] **Step 3: Build and vet**

Run: `go build ./... && go vet ./...`
Expected: clean binary `aperture-mcp`.

- [ ] **Step 4: Commit**

```bash
git add cmd/aperture-mcp/main.go policy.example.json
git commit -m "main: wire tsnet WhoIs resolver, policy, middleware, tools, healthz"
```

---

### Task 8: Operability (Makefile + CI)

**Files:**
- Create: `Makefile`, `.github/workflows/ci.yml`

- [ ] **Step 1: Makefile**

```makefile
.PHONY: run test
run:
	go run ./cmd/aperture-mcp
test:
	go test ./... && go vet ./...
```

- [ ] **Step 2: CI workflow**

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: 'stable' }
      - run: go test ./...
      - run: go vet ./...
```

- [ ] **Step 3: Run the gate locally**

Run: `make test`
Expected: all packages PASS, vet clean.

- [ ] **Step 4: Commit**

```bash
git add Makefile .github/workflows/ci.yml
git commit -m "ops: make run/test and CI (go test + vet)"
```

---

### Task 9: Real-path verification (drives the actual server)

**Files:** none (this task produces observed evidence for the README in Task 10)

This task is the "test through the real path before claiming done" rule. Do it before writing run/test docs so the docs reflect reality.

- [ ] **Step 1: Generate an ephemeral auth key** in the Tailscale admin console (tagged `tag:ci` or reusable), export `TS_AUTHKEY`.

- [ ] **Step 2: Add an `aperture-mcp` cap grant** to the tailnet ACL for your own login (or skip and rely on `policy.json` fallback by copying `policy.example.json` to `policy.json` with your login).

- [ ] **Step 3: Run the server**

Run: `make run`
Expected: log shows the tsnet node coming up and the listener address.

- [ ] **Step 4: Connect a client and call tools.** Use an MCP client over the tailnet (e.g. the SDK's client example, or `mcp` CLI if available) pointed at `http://aperture-mcp:80`. Call `whoami`, `resource.get motd` (allow), `resource.get secret` as a reader identity (deny).

- [ ] **Step 5: Capture the actual audit log lines** for one allow and one deny. Save them verbatim for the README. Confirm a deny produces an error to the client and no value leak.

- [ ] **Step 6: Note anything that did not work** and fix it (loop back to the relevant task). Do not proceed until allow and deny are both observed.

---

### Task 10: Docs (README + PRODUCTION.md), size-capped

**Files:**
- Create: `README.md` (one screen), `PRODUCTION.md` (one screen)

**Progressive disclosure:** README answers "what is this + how do I run/test it" and links down to PRODUCTION.md and the ADR. Do not duplicate the runbook into the README.

- [ ] **Step 1: Write README.md**

Sections, terse:
1. **What it is** (2-3 sentences, the why-pitch verbatim).
2. **Run it** (env vars, `make run`, the cap-grant-or-policy.json choice). Copied from what actually worked in Task 9.
3. **Test it** (`make test`, then the real client calls showing one allow and one deny). The reviewer's explicit "important-to-have".
4. **Audit log** (the two real captured lines from Task 9, one allow one deny).
5. **Built with agents** (short POV: where the agent accelerated, where it failed, the public plugins used to discipline it. No attribution boilerplate.).
6. Links: "Operating it / path to production: PRODUCTION.md. Why identity is ambient: docs/adr/0001."

- [ ] **Step 2: Write PRODUCTION.md** (three short sections)

1. **Runbook.** Real failure modes only, from Task 9 reality: missing/expired `TS_AUTHKEY` (symptom + fix), `WhoIs` returns error (fail-closed: requests deny, log line to look for), no `policy.json` and no cap grant (everyone denied; expected), revoked grant (next call denies). What the operator sees, what to do.
2. **Path to production.** The gap list: grant caching + revocation latency, rate limiting, persistence beyond in-memory, multi-node identity consistency, metrics/tracing beyond the audit log. One line each, with why-deferred.
3. **Threat model.** Ambient identity (no client assertion), fail-closed, tailnet perimeter, secret hygiene. Three or four bullets, links to ADR 0001.

- [ ] **Step 3: Dash + size check**

Run: `grep -rnP '[\x{2012}-\x{2015}]' README.md PRODUCTION.md && echo DASHES || echo clean`
Expected: `clean`. Each file ~one screen; trim if longer.

- [ ] **Step 4: Commit**

```bash
git add README.md PRODUCTION.md
git commit -m "docs: README (verified run/test + audit samples) and PRODUCTION runbook"
```

---

## Self-Review

**Spec coverage:** scope (tsnet serve, ambient WhoIs identity, cap-grant + policy fallback, audit line) maps to Tasks 1,4,5,7 / 2,4 / 3,4 / 6. Tools (whoami + resource store) Task 6. Non-goals respected (no stdio, no OS tools, in-memory). DDD model: domain Task 2, anti-corruption Task 4, dependency rule asserted Task 4 Step 5. Security invariants: ambient Task 6 test, fail-closed Tasks 2/5/6, tailnet perimeter Task 7, secret hygiene Task 1/7. Observability: audit log Task 6, healthz Task 7, real samples Task 9/10. Testing strategy: deny-first Task 2, allow/fallback/ambient Tasks 3/4/6. Deliverables (README, PRODUCTION, CLAUDE.md, ADR, Makefile, CI, policy.example) Tasks 8/10 (CLAUDE.md + ADR already committed). Agentic practices: discrete commits throughout, pinned SDK Task 1, deny-first Task 2.

**Placeholder scan:** SDK-touching tasks (1, 6, 7) intentionally defer exact registration signatures to Task 1's spike and say so explicitly; this is a verification dependency, not a placeholder. All test code is concrete. Pure-domain code (Tasks 2-5) is complete.

**Type consistency:** `Identity{Kind,Name}`, `Grant{Caps}`, `Capability`, `Decision{Allow,Reason,Capability}`, `WhoIsResult{LoginName,Tags,Caps}`, `Resolve`, `Middleware`, `FromContext`, `NewTestContext`, `authorize`, `Store` used consistently across tasks. `CapName` defined Task 4, consumed Task 7.

**Known risk (named, not hidden):** if Task 1 finds `req.Context()` does not propagate to tool handlers, Task 5's design switches to per-request binding via the `getServer` callback; `FromContext` semantics stay identical so Tasks 6/7 are unaffected.
