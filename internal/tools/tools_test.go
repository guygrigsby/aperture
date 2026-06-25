package tools

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func principal(name string, caps ...authz.Capability) Principal {
	g := authz.Grant{Caps: map[authz.Capability]bool{}}
	for _, c := range caps {
		g.Caps[c] = true
	}
	return Principal{ID: authz.Identity{Kind: authz.KindUser, Name: name}, Grant: g}
}

func TestAuthorizeAmbient(t *testing.T) {
	reader := principal("reader@example.com", "resource:read")
	admin := principal("admin@example.com", "resource:read", "resource:admin")

	if err := authorize(reader, discard(), "t", "resource:admin"); !errors.Is(err, authz.ErrDenied) {
		t.Fatal("reader must be denied resource:admin")
	}
	if err := authorize(admin, discard(), "t", "resource:admin"); err != nil {
		t.Fatalf("admin must be allowed: %v", err)
	}
	// Empty principal (e.g. WhoIs failed, fail-closed) denies.
	if err := authorize(Principal{}, discard(), "t", "resource:read"); !errors.Is(err, authz.ErrDenied) {
		t.Fatal("empty principal must deny")
	}
	// A deny returns a generic error; the reason (capability) stays in the audit
	// log, it is never disclosed to the caller.
	err := authorize(reader, discard(), "t", "resource:admin")
	if err.Error() != "denied" {
		t.Fatalf("deny error leaks detail to caller: %q", err.Error())
	}
}

// TestSpoofedIdentityArgumentIgnored is the test named in the spec/ADR: a tool
// call carrying a spoofed identity argument produces the same decision as one
// without it. The tool input types have no identity field, so encoding/json
// drops the extra key, and the bound Principal alone governs authorization.
func TestSpoofedIdentityArgumentIgnored(t *testing.T) {
	// A client tries to assert it is an admin via extra JSON fields.
	const spoofed = `{"key":"secret","identity":"admin@example.com","user":"admin@example.com","role":"admin"}`
	var args GetArgs
	if err := json.Unmarshal([]byte(spoofed), &args); err != nil {
		t.Fatal(err)
	}
	if args.Key != "secret" {
		t.Fatalf("key = %q, want secret", args.Key)
	}

	s := NewStore(DemoItems()...)
	reader := principal("reader@example.com", "resource:read")

	// Same deny whether or not the spoofed payload was present: identity is
	// ambient (the reader Principal), never the tool argument.
	if _, err := s.get(reader, discard(), args.Key); !errors.Is(err, authz.ErrDenied) {
		t.Fatal("spoofed identity argument must not grant access; reader still denied secret")
	}
}

func TestStoreGatedByItemCapability(t *testing.T) {
	s := NewStore(DemoItems()...)
	reader := principal("reader@example.com", "resource:read")
	admin := principal("admin@example.com", "resource:read", "resource:admin")

	// reader reads a public item
	if it, err := s.get(reader, discard(), "motd"); err != nil || it.Value == "" {
		t.Fatalf("reader should read motd: %v", err)
	}
	// reader denied the admin-only item; no value leaks
	if it, err := s.get(reader, discard(), "secret"); !errors.Is(err, authz.ErrDenied) || it.Value != "" {
		t.Fatalf("reader must be denied secret with no leak, got item=%q err=%v", it.Value, err)
	}
	// admin reads it
	if _, err := s.get(admin, discard(), "secret"); err != nil {
		t.Fatalf("admin should read secret: %v", err)
	}
	// list returns only what the principal may read
	if got := len(s.list(reader, discard())); got != 1 {
		t.Fatalf("reader list = %d items, want 1 (public only)", got)
	}
	if got := len(s.list(admin, discard())); got != 2 {
		t.Fatalf("admin list = %d items, want 2", got)
	}
	// put requires admin
	if err := s.put(reader, discard(), Item{Key: "x", Value: "v", Required: "resource:read"}); !errors.Is(err, authz.ErrDenied) {
		t.Fatal("reader must be denied put")
	}
	if err := s.put(admin, discard(), Item{Key: "x", Value: "v", Required: "resource:read"}); err != nil {
		t.Fatalf("admin should put: %v", err)
	}
}
