// Package authz is the authorization domain. It decides allow/deny from an
// Identity, its Grant, and the Capability a tool requires. It imports nothing
// from tailscale.com; vendor types stop at internal/tailnet (the
// anti-corruption layer). See docs/adr/0001-identity-is-ambient.md.
package authz

import (
	"errors"
	"fmt"
)

// ErrDenied is returned by callers that gate on a denied Decision.
var ErrDenied = errors.New("denied")

// Capability is a named permission, e.g. "resource:read".
type Capability string

// TagPrefix is the prefix Tailscale puts on ACL tags ("tag:ci").
const TagPrefix = "tag:"

// IdentityKind distinguishes a user node from a tagged node.
type IdentityKind int

const (
	KindUser IdentityKind = iota
	KindTagged
)

// Identity is the resolved principal behind a connection.
type Identity struct {
	Kind IdentityKind
	Name string // user login, or tag name (without the "tag:" prefix)
}

func (i Identity) String() string {
	if i.Kind == KindTagged {
		return TagPrefix + i.Name
	}
	return i.Name
}

// Grant is the set of capabilities an Identity holds.
type Grant struct {
	Caps map[Capability]bool
}

// Has reports whether the grant includes capability c. A nil cap map reads as
// false, so a zero-value Grant denies everything (fail closed).
func (g Grant) Has(c Capability) bool { return g.Caps[c] }

// Tool is a callable that requires a Capability to invoke.
type Tool struct {
	Name     string
	Required Capability
}

// Decision is the auditable output of an authorization check.
type Decision struct {
	Allow      bool
	Reason     string
	Capability Capability
}

// Decide is the single place an allow/deny is produced. Fail closed: an empty
// grant or a missing capability is a deny carrying a reason for the audit line.
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
