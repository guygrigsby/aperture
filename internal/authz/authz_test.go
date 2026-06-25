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
