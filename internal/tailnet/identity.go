// Package tailnet is the anti-corruption layer between Tailscale and the authz
// domain. Resolve and WhoIsResult are vendor-free and unit-testable; the raw
// tailscale WhoIs projection into WhoIsResult lives alongside the tsnet wiring
// (see ProjectWhoIs). The domain (internal/authz) imports nothing from
// tailscale.com.
package tailnet

import (
	"sort"
	"strings"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
)

// CapName is the app-capability key we read from the tailnet grant CapMap.
const CapName = "grigsby.dev/cap/aperture-mcp"

// WhoIsResult is the vendor-free projection of a Tailscale WhoIs lookup.
type WhoIsResult struct {
	LoginName   string              // set for user nodes
	Tags        map[string]struct{} // set of ACL tags (with "tag:" prefix) for tagged nodes; O(1) membership
	Caps        []authz.Capability  // capabilities merged from the CapMap grant
	HasCapGrant bool                // the app-cap key was present in the CapMap, even if it granted no caps
}

// Resolve maps a WhoIsResult to a domain Identity and Grant. Precedence:
//  1. CapMap caps, if any, win.
//  2. An app-cap grant that is present but conveys no caps is an authoritative
//     deny: it yields an empty grant and the fallback policy is NOT consulted.
//     ("grant present, caps: []" must not be overridden by policy.json.)
//  3. Only when no app-cap grant is present at all do we consult the fallback.
//
// For a tagged node the fallback grant is the union of the policy's caps across
// ALL of the node's tags, not an arbitrary first one. A nil fallback (or no
// policy) yields an empty grant, which denies everything.
func Resolve(w WhoIsResult, fallback *authz.Policy) (authz.Identity, authz.Grant) {
	tagged := len(w.Tags) > 0
	var (
		id   authz.Identity
		tags []string
	)
	if tagged {
		tags = sortedStrippedTags(w.Tags)
		id = authz.Identity{Kind: authz.KindTagged, Name: strings.Join(tags, ",")}
	} else {
		id = authz.Identity{Kind: authz.KindUser, Name: w.LoginName}
	}

	if len(w.Caps) > 0 {
		return id, grantFromCaps(w.Caps)
	}
	if w.HasCapGrant {
		// Authoritative empty grant: do not fall through to the policy.
		return id, authz.Grant{Caps: map[authz.Capability]bool{}}
	}

	// No app-cap grant: consult the fallback policy.
	if tagged {
		// Union across every tag; which tag "wins" never matters.
		g := authz.Grant{Caps: map[authz.Capability]bool{}}
		for _, t := range tags {
			for c := range fallback.GrantFor(authz.Identity{Kind: authz.KindTagged, Name: t}).Caps {
				g.Caps[c] = true
			}
		}
		return id, g
	}
	return id, fallback.GrantFor(id) // GrantFor is nil-safe; empty grant if no policy
}

func grantFromCaps(caps []authz.Capability) authz.Grant {
	g := authz.Grant{Caps: make(map[authz.Capability]bool, len(caps))}
	for _, c := range caps {
		g.Caps[c] = true
	}
	return g
}

// sortedStrippedTags returns the node's tags without the "tag:" prefix, sorted
// for a deterministic identity name and stable policy iteration.
func sortedStrippedTags(tags map[string]struct{}) []string {
	out := make([]string, 0, len(tags))
	for t := range tags {
		out = append(out, strings.TrimPrefix(t, authz.TagPrefix))
	}
	sort.Strings(out)
	return out
}
