package tailnet

import (
	"testing"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
)

func tagSet(tags ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		m[t] = struct{}{}
	}
	return m
}

func TestResolve(t *testing.T) {
	pol := &authz.Policy{
		Users: map[string][]authz.Capability{"reader@example.com": {"resource:read"}},
		Tags: map[string][]authz.Capability{
			"ci":  {"resource:read"},
			"ops": {"resource:admin"},
		},
	}

	tests := []struct {
		name     string
		who      WhoIsResult
		fallback *authz.Policy
		wantKind authz.IdentityKind
		wantName string
		has      []authz.Capability // capabilities expected present
		lacks    []authz.Capability // capabilities expected absent
	}{
		{
			name:     "user: CapMap caps win over fallback",
			who:      WhoIsResult{LoginName: "admin@example.com", Caps: []authz.Capability{"resource:read", "resource:admin"}},
			fallback: pol,
			wantKind: authz.KindUser, wantName: "admin@example.com",
			has: []authz.Capability{"resource:admin"},
		},
		{
			name:     "user: no caps falls back to policy",
			who:      WhoIsResult{LoginName: "reader@example.com"},
			fallback: pol,
			wantKind: authz.KindUser, wantName: "reader@example.com",
			has: []authz.Capability{"resource:read"}, lacks: []authz.Capability{"resource:admin"},
		},
		{
			name:     "user: no caps and no fallback is empty",
			who:      WhoIsResult{LoginName: "reader@example.com"},
			fallback: nil,
			wantKind: authz.KindUser, wantName: "reader@example.com",
			lacks: []authz.Capability{"resource:read"},
		},
		{
			name:     "tagged: single tag, prefix stripped",
			who:      WhoIsResult{Tags: tagSet("tag:ci")},
			fallback: pol,
			wantKind: authz.KindTagged, wantName: "ci",
			has: []authz.Capability{"resource:read"}, lacks: []authz.Capability{"resource:admin"},
		},
		{
			name:     "tagged: multi-tag unions policy across ALL tags",
			who:      WhoIsResult{Tags: tagSet("tag:ops", "tag:ci")},
			fallback: pol,
			wantKind: authz.KindTagged, wantName: "ci,ops", // sorted, deterministic
			has: []authz.Capability{"resource:read", "resource:admin"},
		},
		{
			// An app-cap grant present with caps:[] is an authoritative deny;
			// policy.json must NOT override it.
			name:     "authoritative empty grant is not overridden by fallback",
			who:      WhoIsResult{LoginName: "reader@example.com", HasCapGrant: true},
			fallback: pol, // would otherwise grant reader resource:read
			wantKind: authz.KindUser, wantName: "reader@example.com",
			lacks:    []authz.Capability{"resource:read"},
		},
		{
			name:     "tagged: nil fallback yields an empty grant",
			who:      WhoIsResult{Tags: tagSet("tag:ci")},
			fallback: nil,
			wantKind: authz.KindTagged, wantName: "ci",
			lacks:    []authz.Capability{"resource:read"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, g := Resolve(tc.who, tc.fallback)
			if id.Kind != tc.wantKind || id.Name != tc.wantName {
				t.Fatalf("identity = %+v, want kind=%v name=%q", id, tc.wantKind, tc.wantName)
			}
			for _, c := range tc.has {
				if !g.Has(c) {
					t.Errorf("missing expected cap %q", c)
				}
			}
			for _, c := range tc.lacks {
				if g.Has(c) {
					t.Errorf("unexpected cap %q", c)
				}
			}
		})
	}
}
