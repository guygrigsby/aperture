package tailnet

import (
	"slices"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
)

func TestProjectWhoIsNilResponse(t *testing.T) {
	if _, err := ProjectWhoIs(nil); err == nil {
		t.Fatal("nil response must error (fail closed), not panic")
	}
}

func TestProjectWhoIsTags(t *testing.T) {
	resp := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{Tags: []string{"tag:ci", "tag:ops"}},
	}
	got, err := ProjectWhoIs(resp)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Tags["tag:ci"]; !ok {
		t.Fatalf("tag:ci not projected, got %v", got.Tags)
	}
	if _, ok := got.Tags["tag:ops"]; !ok {
		t.Fatalf("tag:ops not projected, got %v", got.Tags)
	}
}

func TestProjectWhoIsMalformedCapErrors(t *testing.T) {
	resp := &apitype.WhoIsResponse{
		UserProfile: &tailcfg.UserProfile{LoginName: "admin@example.com"},
		CapMap: tailcfg.PeerCapMap{
			CapName: {tailcfg.RawMessage("{not valid json")},
		},
	}
	if _, err := ProjectWhoIs(resp); err == nil {
		t.Fatal("malformed cap grant must return an error so the caller fails closed, not fall through to the policy")
	}
}

func TestProjectWhoIsMergesCaps(t *testing.T) {
	resp := &apitype.WhoIsResponse{
		UserProfile: &tailcfg.UserProfile{LoginName: "admin@example.com"},
		CapMap: tailcfg.PeerCapMap{
			CapName: {
				tailcfg.RawMessage(`{"caps":["resource:read"]}`),
				tailcfg.RawMessage(`{"caps":["resource:admin"]}`),
			},
		},
	}
	got, err := ProjectWhoIs(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []authz.Capability{"resource:read", "resource:admin"} {
		if !slices.Contains(got.Caps, want) {
			t.Fatalf("caps = %v, want %q merged across grant rules", got.Caps, want)
		}
	}
}

func TestProjectWhoIsEmptyGrantIsPresent(t *testing.T) {
	// An app-cap grant present with caps:[] must register as HasCapGrant so
	// Resolve treats it as authoritative and does not fall back to policy.
	resp := &apitype.WhoIsResponse{
		UserProfile: &tailcfg.UserProfile{LoginName: "reader@example.com"},
		CapMap:      tailcfg.PeerCapMap{CapName: {tailcfg.RawMessage(`{"caps":[]}`)}},
	}
	got, err := ProjectWhoIs(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasCapGrant {
		t.Fatal("a present grant with caps:[] must set HasCapGrant")
	}
	if len(got.Caps) != 0 {
		t.Fatalf("caps = %v, want none", got.Caps)
	}
}
