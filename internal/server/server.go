// Package server is the HTTP side of `slk serve`: a small REST API on
// loopback that a browser page (Workcenter) calls with a per-run password.
//
// The package owns transport and security only: the loopback bind, the
// Host and Origin checks, CORS, HTTP basic auth, JSON encoding and
// credential redaction in logs. Everything that touches Slack lives behind
// the Backend interface, implemented in cmd/slk, so this package never sees
// an xoxc token or the d cookie and stays independent of upstream slk.
//
// The contract mirrors `opencode serve`, which Workcenter already speaks:
//
//   - binds 127.0.0.1 only;
//   - a random password per run (SLK_SERVER_PASSWORD overrides it), sent as
//     HTTP basic auth with user "slk" on every request;
//   - --cors names one exact origin, and a request carrying any other
//     Origin is refused with 403 rather than merely missing CORS headers.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Username is the fixed HTTP basic auth user.
const Username = "slk"

// maxBodyBytes bounds every request body. No v0 endpoint needs more than a
// short message.
const maxBodyBytes = 64 << 10

// Backend is what the server needs from the Slack side.
type Backend interface {
	// Status reports auth and per-workspace connection state. It must not
	// block on the network.
	Status() (AuthStatus, []WorkspaceStatus)
	// Workspaces lists the workspaces that are connected right now.
	Workspaces() []Workspace
	// RefreshAuth re-reads the live Slack desktop session and reconnects.
	RefreshAuth(ctx context.Context) error
}

// Config configures a Server.
type Config struct {
	// Port to listen on at 127.0.0.1. 0 picks a free port.
	Port int
	// Origin is the one browser origin allowed to call the server, as
	// returned by NormalizeOrigin. Empty refuses every request that
	// carries an Origin header (non-browser clients still work).
	Origin   string
	Password string
	Version  string
	Backend  Backend
	// Logger receives one line per request (method, path, status). It
	// should write through a Redactor. Nil discards.
	Logger *log.Logger
	// Now is for tests; nil means time.Now.
	Now func() time.Time
}

// Server is the `slk serve` HTTP server.
type Server struct {
	cfg       Config
	startedAt time.Time
	listener  net.Listener
	http      *http.Server
	// allowedHosts is filled by Listen once the port is known.
	allowedHosts map[string]bool
}

// New validates cfg and builds a Server. Call Listen, then Serve.
func New(cfg Config) (*Server, error) {
	if cfg.Password == "" {
		return nil, errors.New("server: empty password")
	}
	if cfg.Backend == nil {
		return nil, errors.New("server: nil backend")
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("server: invalid port %d", cfg.Port)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(discard{}, "", 0)
	}
	s := &Server{cfg: cfg, startedAt: cfg.Now()}
	return s, nil
}

// Listen binds 127.0.0.1:Port. There is deliberately no way to bind any
// other address: this server can post to Slack as the signed-in user.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.cfg.Port)))
	if err != nil {
		return err
	}
	s.useListener(ln)
	return nil
}

func (s *Server) useListener(ln net.Listener) {
	s.listener = ln
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	s.allowedHosts = map[string]bool{
		"127.0.0.1:" + port: true,
		"localhost:" + port: true,
	}
	s.http = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: the event stream (WC-4) is long-lived.
		ErrorLog: s.cfg.Logger,
	}
}

// Addr is the bound address, e.g. "127.0.0.1:4097". Empty before Listen.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// URL is the base URL clients use.
func (s *Server) URL() string { return "http://" + s.Addr() }

// Serve runs until Shutdown. It returns nil after a clean shutdown.
func (s *Server) Serve() error {
	if s.http == nil {
		return errors.New("server: Serve before Listen")
	}
	err := s.http.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting requests and waits for in-flight ones.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

// Handler returns the full handler: guard (host, origin, CORS, auth) in
// front of the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/health", s.handleHealth)
	mux.HandleFunc("GET /v0/workspaces", s.handleWorkspaces)
	mux.HandleFunc("POST /v0/auth/refresh", s.handleRefresh)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
	})
	return s.logRequests(s.guard(mux))
}

// Health is the GET /v0/health body. It carries no credentials.
type Health struct {
	OK         bool              `json:"ok"`
	Server     ServerInfo        `json:"server"`
	Auth       AuthStatus        `json:"auth"`
	Workspaces []WorkspaceStatus `json:"workspaces"`
}

// ServerInfo describes this process.
type ServerInfo struct {
	Version       string    `json:"version"`
	StartedAt     time.Time `json:"startedAt"`
	UptimeSeconds int64     `json:"uptimeSeconds"`
	Listen        string    `json:"listen"`
	CORSOrigin    string    `json:"corsOrigin"`
}

// Auth states.
const (
	AuthStarting   = "starting"
	AuthOK         = "ok"
	AuthRefreshing = "refreshing"
	AuthExpired    = "expired"
	AuthError      = "error"
)

// AuthStatus describes the Slack desktop session slk serve is using.
type AuthStatus struct {
	// State is one of the Auth* constants.
	State string `json:"state"`
	// Source is where the current tokens came from: "desktop" when the
	// last refresh read the live Slack desktop session, "cached" when it
	// fell back to the tokens saved by `slk --add-workspace`.
	Source        string     `json:"source,omitempty"`
	LastRefreshAt *time.Time `json:"lastRefreshAt,omitempty"`
	LastReason    string     `json:"lastRefreshReason,omitempty"`
	// Error is a redacted, human-readable reason when State isn't ok.
	Error string `json:"error,omitempty"`
}

// Workspace connection states.
const (
	WorkspaceConnecting  = "connecting"
	WorkspaceConnected   = "connected"
	WorkspaceAuthExpired = "auth_expired"
	WorkspaceError       = "error"
)

// WorkspaceStatus is one configured workspace's connection state.
type WorkspaceStatus struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	State         string     `json:"state"`
	UserID        string     `json:"userId,omitempty"`
	LastCheckedAt *time.Time `json:"lastCheckedAt,omitempty"`
	Error         string     `json:"error,omitempty"`
}

// Workspace is a connected workspace, as listed by GET /v0/workspaces.
type Workspace struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain,omitempty"`
	UserID string `json:"userId,omitempty"`
}

func (s *Server) health() Health {
	auth, ws := s.cfg.Backend.Status()
	if ws == nil {
		ws = []WorkspaceStatus{}
	}
	connected := 0
	for _, w := range ws {
		if w.State == WorkspaceConnected {
			connected++
		}
	}
	now := s.cfg.Now()
	return Health{
		OK: auth.State == AuthOK && connected > 0,
		Server: ServerInfo{
			Version:       s.cfg.Version,
			StartedAt:     s.startedAt.UTC(),
			UptimeSeconds: int64(now.Sub(s.startedAt) / time.Second),
			Listen:        s.Addr(),
			CORSOrigin:    s.cfg.Origin,
		},
		Auth:       auth,
		Workspaces: ws,
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.health())
}

func (s *Server) handleWorkspaces(w http.ResponseWriter, r *http.Request) {
	list := s.cfg.Backend.Workspaces()
	if list == nil {
		list = []Workspace{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"workspaces": list})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	// The outcome is in the health body either way; a failed refresh is
	// a state, not a transport error.
	_ = s.cfg.Backend.RefreshAuth(ctx)
	writeJSON(w, http.StatusOK, s.health())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var b errorBody
	b.Error.Code = code
	b.Error.Message = message
	writeJSON(w, status, b)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
