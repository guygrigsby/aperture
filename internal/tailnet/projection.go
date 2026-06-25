package tailnet

import (
	"errors"
	"fmt"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
)

// capRule is the JSON shape of our app-capability grant in the tailnet policy:
//
//	"grants": [{ "src": [...], "dst": [...], "app": {
//	    "grigsby.dev/cap/aperture-mcp": [{ "caps": ["resource:read", "resource:admin"] }] }}]
type capRule struct {
	Caps []authz.Capability `json:"caps"`
}

// ProjectWhoIs maps a raw Tailscale WhoIs response into the vendor-free
// WhoIsResult. Capabilities are merged across every matching grant rule (not
// first-wins). This is the only place tailscale types touch our identity model.
//
// A nil response or a malformed cap grant returns an error rather than yielding
// no caps. The caller must fail closed on that error (bind an empty principal,
// do not fall through to the fallback policy); cmd/aperture-mcp's getServer does
// exactly that.
func ProjectWhoIs(resp *apitype.WhoIsResponse) (WhoIsResult, error) {
	if resp == nil {
		return WhoIsResult{}, errors.New("nil whois response")
	}
	var r WhoIsResult
	if resp.UserProfile != nil {
		r.LoginName = resp.UserProfile.LoginName
	}
	if resp.Node != nil && len(resp.Node.Tags) > 0 {
		r.Tags = make(map[string]struct{}, len(resp.Node.Tags))
		for _, t := range resp.Node.Tags {
			r.Tags[t] = struct{}{}
		}
	}
	rules, err := tailcfg.UnmarshalCapJSON[capRule](resp.CapMap, CapName)
	if err != nil {
		return WhoIsResult{}, fmt.Errorf("parse cap grant %s: %w", CapName, err)
	}
	// Presence of the grant key is authoritative, independent of cap count: a
	// grant with caps:[] means "explicitly no caps", not "no grant" (see Resolve).
	r.HasCapGrant = len(rules) > 0
	for _, rule := range rules {
		r.Caps = append(r.Caps, rule.Caps...)
	}
	return r, nil
}
