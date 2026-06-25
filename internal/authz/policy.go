package authz

import (
	"encoding/json"
	"fmt"
	"os"
)

// Policy is the local fallback consulted when a caller has no capability grant
// in their tailnet CapMap. It lets reviewers exercise allow/deny without
// editing their tailnet ACL.
type Policy struct {
	Users map[string][]Capability `json:"users"`
	Tags  map[string][]Capability `json:"tags"`
}

// LoadPolicy reads and parses a policy file.
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

// GrantFor returns the capabilities the policy assigns to an identity, or an
// empty (non-nil) grant if the identity is not listed.
func (p *Policy) GrantFor(id Identity) Grant {
	if p == nil { // no policy configured: fail closed, never panic
		return Grant{Caps: map[Capability]bool{}}
	}
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
