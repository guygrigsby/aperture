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

func TestLoadPolicyMissingFile(t *testing.T) {
	if _, err := LoadPolicy(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("missing file should error")
	}
}
