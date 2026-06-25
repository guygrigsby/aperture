// Package tools exposes the MCP tool surface. Every tool authorizes through
// authz.Decide against the session Principal bound at registration; no tool
// accepts a caller-supplied identity, so identity cannot be spoofed (ambient
// identity, see docs/adr/0001-identity-is-ambient.md). Tool descriptions stay
// terse; detail surfaces on demand via whoami output.
package tools

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
)

// Principal is the identity and grant resolved for a session.
type Principal struct {
	ID    authz.Identity
	Grant authz.Grant
}

// resolved reports whether an identity was established for this session. An
// empty Principal (WhoIs failed) is unresolved and must be denied (fail closed).
func (p Principal) resolved() bool { return p.ID.Name != "" }

// GetArgs and PutArgs are the tool input types. They carry only data, no
// identity/user/role field, so a client cannot assert who it is: unknown JSON
// keys (e.g. a spoofed "identity") are dropped by encoding/json. This is the
// structural enforcement of the ambient-identity invariant (ADR 0001).
type GetArgs struct {
	Key string `json:"key" jsonschema:"the resource key to read"`
}

type PutArgs struct {
	Key      string `json:"key" jsonschema:"the resource key"`
	Value    string `json:"value" jsonschema:"the value to store"`
	Required string `json:"required" jsonschema:"capability required to read it later"`
}

// WhoamiOut and ListOut are structured tool outputs (the SDK serializes them to
// both StructuredContent and JSON text), so clients get machine-readable data
// rather than a hand-formatted string.
type WhoamiOut struct {
	Identity     string   `json:"identity"`
	Capabilities []string `json:"capabilities"`
}

type ListOut struct {
	Keys []string `json:"keys"`
}

// audit emits one structured authorization line. tool and capability are
// separate fields so log queries can filter on either without ambiguity.
func audit(log *slog.Logger, caller, tool string, capability authz.Capability, decision, reason string) {
	log.Info("authz",
		"caller", caller,
		"tool", tool,
		"capability", string(capability),
		"decision", decision,
		"reason", reason,
	)
}

// authorize is the single gate. It decides, emits the audit line, and returns a
// generic authz.ErrDenied on deny. The denial reason is recorded only in the
// audit log, never returned to the caller (no capability disclosure).
func authorize(p Principal, log *slog.Logger, tool string, required authz.Capability) error {
	d := authz.Decide(p.ID, p.Grant, required)
	decision := "deny"
	if d.Allow {
		decision = "allow"
	}
	audit(log, p.ID.String(), tool, required, decision, d.Reason)
	if !d.Allow {
		return authz.ErrDenied
	}
	return nil
}

// denyIfUnresolved returns a deny result with a consistent "unresolved" audit
// line when no identity was established for the session (WhoIs failed), else
// nil. Used by every tool so an operator querying caller=unresolved catches all
// of them, not just some.
func denyIfUnresolved(p Principal, log *slog.Logger, tool string) *mcp.CallToolResult {
	if p.resolved() {
		return nil
	}
	audit(log, "unresolved", tool, "", "deny", "identity not resolved")
	return errText(authz.ErrDenied)
}

// Item is a stored resource; Required names the capability needed to read it.
type Item struct {
	Key      string           `json:"key"`
	Value    string           `json:"value"`
	Required authz.Capability `json:"required"`
}

// DemoItems is the seed data for the example store, injected into NewStore by
// the composition root. Kept out of NewStore so the store has no baked-in data.
func DemoItems() []Item {
	return []Item{
		{Key: "motd", Value: "hello tailnet", Required: "resource:read"},
		{Key: "secret", Value: "admin-only value", Required: "resource:admin"},
	}
}

// Store is a tiny in-memory resource store. In-memory, resets on restart;
// persistence is a PRODUCTION.md gap, not needed to show the authz boundary.
type Store struct {
	mu    sync.RWMutex
	items map[string]Item
}

// NewStore builds a store seeded with the given items (dependency injection;
// the demo seed comes from DemoItems).
func NewStore(items ...Item) *Store {
	m := make(map[string]Item, len(items))
	for _, it := range items {
		m[it.Key] = it
	}
	return &Store{items: m}
}

func (s *Store) get(p Principal, log *slog.Logger, key string) (Item, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	it, ok := s.items[key]
	if !ok {
		return Item{}, fmt.Errorf("no such item %q", key)
	}
	if err := authorize(p, log, "resource.get", it.Required); err != nil {
		return Item{}, err // generic deny, no value leak
	}
	return it, nil
}

func (s *Store) list(p Principal, log *slog.Logger) []Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := len(s.items)
	var out []Item
	for _, it := range s.items {
		if authz.Decide(p.ID, p.Grant, it.Required).Allow {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	// One summary audit line; per-item decisions would flood the log.
	audit(log, p.ID.String(), "resource.list", "", "filter", fmt.Sprintf("%d of %d visible", len(out), total))
	return out
}

func (s *Store) put(p Principal, log *slog.Logger, it Item) error {
	if err := authorize(p, log, "resource.put", "resource:admin"); err != nil {
		return err
	}
	if it.Key == "" || it.Required == "" {
		return fmt.Errorf("key and required capability must be non-empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[it.Key] = it
	return nil
}

// Register wires the tool surface onto a per-session server bound to p.
func Register(srv *mcp.Server, p Principal, store *Store, log *slog.Logger) {
	mcp.AddTool(srv, &mcp.Tool{Name: "whoami", Description: "report the caller's resolved tailnet identity and capabilities"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, WhoamiOut, error) {
			// Fail closed: an unresolved identity (WhoIs failed) is denied and
			// audited, like every other tool. ADR 0001.
			if r := denyIfUnresolved(p, log, "whoami"); r != nil {
				return r, WhoamiOut{}, nil
			}
			audit(log, p.ID.String(), "whoami", "", "allow", "introspection")
			return nil, WhoamiOut{Identity: p.ID.String(), Capabilities: sortedCaps(p.Grant)}, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "resource.list", Description: "list resources the caller may read"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ListOut, error) {
			if r := denyIfUnresolved(p, log, "resource.list"); r != nil {
				return r, ListOut{}, nil
			}
			items := store.list(p, log)
			keys := make([]string, 0, len(items))
			for _, it := range items {
				keys = append(keys, it.Key)
			}
			return nil, ListOut{Keys: keys}, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "resource.get", Description: "read a resource by key, if authorized"},
		func(_ context.Context, _ *mcp.CallToolRequest, in GetArgs) (*mcp.CallToolResult, any, error) {
			if r := denyIfUnresolved(p, log, "resource.get"); r != nil {
				return r, nil, nil
			}
			it, err := store.get(p, log, in.Key)
			if err != nil {
				return errText(err), nil, nil
			}
			return text(it.Value), nil, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "resource.put", Description: "store a resource, requires resource:admin"},
		func(_ context.Context, _ *mcp.CallToolRequest, in PutArgs) (*mcp.CallToolResult, any, error) {
			if r := denyIfUnresolved(p, log, "resource.put"); r != nil {
				return r, nil, nil
			}
			err := store.put(p, log, Item{Key: in.Key, Value: in.Value, Required: authz.Capability(in.Required)})
			if err != nil {
				return errText(err), nil, nil
			}
			return text("stored " + in.Key), nil, nil
		})
}

func sortedCaps(g authz.Grant) []string {
	caps := make([]string, 0, len(g.Caps))
	for c := range g.Caps {
		caps = append(caps, string(c))
	}
	sort.Strings(caps)
	return caps
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// errText returns a tool-level error result (no transport error, no value leak).
func errText(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}
}
