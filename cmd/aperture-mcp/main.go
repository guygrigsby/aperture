// Command aperture-mcp is an identity-aware MCP server. It serves over the
// tailnet via tsnet, identifies each caller from their Tailscale identity
// (WhoIs on the connection, never client-asserted), and authorizes every tool
// call against that identity's capability grants. One structured audit line is
// emitted per authorization decision. See docs/specs and docs/adr/0001.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"

	"github.com/guygrigsby/aperture-mcp/internal/authz"
	"github.com/guygrigsby/aperture-mcp/internal/tailnet"
	"github.com/guygrigsby/aperture-mcp/internal/tools"
)

// stateDir holds the tsnet node state and, by default, the address file.
const stateDir = "tsnet-state"

func main() {
	log := newLogger()
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// newLogger emits structured JSON. Set APERTURE_DEBUG to include tsnet's verbose
// bring-up logs (routed through slog at debug); at the default level the stream
// is only this server's own structured lines.
func newLogger() *slog.Logger {
	level := slog.LevelInfo
	if os.Getenv("APERTURE_DEBUG") != "" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func run(log *slog.Logger) error {
	authKey := os.Getenv("TS_AUTHKEY")
	if authKey == "" {
		return errors.New("TS_AUTHKEY is required (ephemeral key from the Tailscale admin console)")
	}
	hostname := envOr("TS_HOSTNAME", "aperture-mcp")
	policyPath := envOr("APERTURE_POLICY", "policy.json")

	// Optional local fallback policy. Absent file means cap-grant-only mode.
	// Load directly (no Stat-then-read TOCTOU); a missing file is not an error.
	policy, err := authz.LoadPolicy(policyPath)
	switch {
	case err == nil:
		log.Info("loaded fallback policy", "path", policyPath)
	case errors.Is(err, os.ErrNotExist):
		policy = nil
		log.Info("no fallback policy, authorizing from tailnet grants only", "path", policyPath)
	default:
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Route tsnet's chatty, unstructured logs through slog at debug so the
	// default-level stream stays consistently structured (only our own lines).
	tsLogf := func(format string, args ...any) { log.Debug("tsnet", "line", fmt.Sprintf(format, args...)) }
	ts := &tsnet.Server{
		Hostname: hostname, Dir: stateDir, AuthKey: authKey, Ephemeral: true,
		Logf:     tsLogf,
		UserLogf: tsLogf,
	}
	defer ts.Close()
	status, err := ts.Up(ctx)
	if err != nil {
		return err
	}

	// PoLP guardrail: when APERTURE_REQUIRE_TAG is set, refuse to serve unless
	// this node actually came up with that ACL tag. Catches a too-privileged
	// (e.g. user-scoped) auth key before the server ever accepts a request.
	if want := os.Getenv("APERTURE_REQUIRE_TAG"); want != "" {
		tags := selfTags(status)
		if !slices.Contains(tags, want) {
			return fmt.Errorf("startup guardrail: node is not tagged %q (got %v); refusing to serve with a more-privileged identity", want, tags)
		}
		log.Info("startup guardrail passed", "required_tag", want)
	}
	lc, err := ts.LocalClient()
	if err != nil {
		return err
	}

	store := tools.NewStore(tools.DemoItems()...)

	// getServer resolves the caller per session from the connection's remote
	// address (ambient identity) and binds a server whose tools close over the
	// resolved principal. Fail closed: a WhoIs error binds an empty principal,
	// so every tool denies and still logs an audit line.
	getServer := func(req *http.Request) *mcp.Server {
		var p tools.Principal
		// Bound the WhoIs call so it cannot hang; still derived from ctx, so a
		// shutdown cancels it and the session fails closed (intended).
		whoCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		switch resp, err := lc.WhoIs(whoCtx, req.RemoteAddr); {
		case err != nil:
			log.Warn("whois failed, binding empty principal (fail closed)", "remote", req.RemoteAddr, "err", err)
		default:
			who, perr := tailnet.ProjectWhoIs(resp)
			if perr != nil {
				// Malformed cap grant: deny, do not fall through to the policy.
				log.Error("cap grant parse failed, binding empty principal (fail closed)", "remote", req.RemoteAddr, "err", perr)
			} else {
				id, grant := tailnet.Resolve(who, policy)
				p = tools.Principal{ID: id, Grant: grant}
			}
		}
		srv := mcp.NewServer(&mcp.Implementation{Name: "aperture-mcp", Version: "0.1.0"}, nil)
		tools.Register(srv, p, store, log)
		return srv
	}

	mux := http.NewServeMux()
	mux.Handle("/", mcp.NewStreamableHTTPHandler(getServer, nil))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ln, err := ts.Listen("tcp", ":80")
	if err != nil {
		return err
	}
	ip4, _ := ts.TailscaleIPs()
	ipAddr := "(no ipv4)"
	if ip4.IsValid() {
		ipAddr = fmt.Sprintf("http://%s:80", ip4)
	}
	log.Info("serving",
		"hostname", hostname,
		"magicdns", fmt.Sprintf("http://%s:80", hostname),
		"ip", ipAddr,
	)

	// Readiness handoff: write the address to a file so a harness can learn the
	// endpoint without scraping logs (the file appearing is also the ready
	// signal). Defaults to the state dir; APERTURE_ADDR_FILE overrides the path.
	addrFile := envOr("APERTURE_ADDR_FILE", filepath.Join(stateDir, "addr"))
	if ip4.IsValid() {
		if err := os.WriteFile(addrFile, []byte(ipAddr+"\n"), 0o600); err != nil {
			log.Warn("could not write address file", "path", addrFile, "err", err)
		}
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx) // drain in-flight calls, then Close on timeout
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func selfTags(status *ipnstate.Status) []string {
	if status == nil || status.Self == nil || status.Self.Tags == nil {
		return nil
	}
	return status.Self.Tags.AsSlice()
}
