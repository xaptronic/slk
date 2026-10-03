package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testOrigin   = "https://workcenter.quick.shopify.io"
	testPassword = "correct-horse-battery-staple"
)

type fakeBackend struct {
	mu        sync.Mutex
	auth      AuthStatus
	status    []WorkspaceStatus
	list      []Workspace
	refreshes int
}

func (f *fakeBackend) Status() (AuthStatus, []WorkspaceStatus) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auth, f.status
}

func (f *fakeBackend) Workspaces() []Workspace {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.list
}

func (f *fakeBackend) RefreshAuth(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	f.auth.State = AuthOK
	return nil
}

func newBackend() *fakeBackend {
	return &fakeBackend{
		auth:   AuthStatus{State: AuthOK, Source: "desktop"},
		status: []WorkspaceStatus{{ID: "E017D49VC3F", Name: "Shopify", State: WorkspaceConnected, UserID: "U1"}},
		list:   []Workspace{{ID: "E017D49VC3F", Name: "Shopify", Domain: "shopify", UserID: "U1"}},
	}
}

// start runs a real server on 127.0.0.1:0 so the Host check sees the
// actual bound port.
func start(t *testing.T, b Backend, logs io.Writer) *Server {
	t.Helper()
	if logs == nil {
		logs = io.Discard
	}
	s, err := New(Config{
		Port:     0,
		Origin:   testOrigin,
		Password: testPassword,
		Version:  "test",
		Backend:  b,
		Logger:   log.New(logs, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return s
}

type req struct {
	method, path, origin, user, pass, host string
	auth                                   bool
	header                                 map[string]string
}

func do(t *testing.T, s *Server, r req) *http.Response {
	t.Helper()
	if r.method == "" {
		r.method = http.MethodGet
	}
	hr, err := http.NewRequest(r.method, s.URL()+r.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.origin != "" {
		hr.Header.Set("Origin", r.origin)
	}
	if r.auth {
		hr.SetBasicAuth(r.user, r.pass)
	}
	if r.host != "" {
		hr.Host = r.host
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func authed(path string) req {
	return req{path: path, auth: true, user: Username, pass: testPassword}
}

func TestAuthRequired(t *testing.T) {
	s := start(t, newBackend(), nil)
	cases := []struct {
		name string
		r    req
	}{
		{"no auth", req{path: "/v0/health"}},
		{"wrong password", req{path: "/v0/health", auth: true, user: Username, pass: "nope"}},
		{"wrong user", req{path: "/v0/health", auth: true, user: "opencode", pass: testPassword}},
		{"empty password", req{path: "/v0/health", auth: true, user: Username}},
		{"unknown route", req{path: "/v0/nope"}},
		{"workspaces", req{path: "/v0/workspaces"}},
		{"refresh", req{method: http.MethodPost, path: "/v0/auth/refresh"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := do(t, s, c.r)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if resp.Header.Get("WWW-Authenticate") == "" {
				t.Error("missing WWW-Authenticate")
			}
		})
	}
}

func TestOriginRefused(t *testing.T) {
	s := start(t, newBackend(), nil)
	for _, origin := range []string{
		"https://evil.example",
		"null", // sandboxed iframes, e.g. Workcenter widgets
		"http://workcenter.quick.shopify.io",
		"https://workcenter.quick.shopify.io.evil.example",
		"https://workcenter.quick.shopify.io/",
	} {
		t.Run(origin, func(t *testing.T) {
			// Even with the right password.
			r := authed("/v0/health")
			r.origin = origin
			resp := do(t, s, r)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("Access-Control-Allow-Origin = %q, want none", got)
			}
			// Preflight from the wrong origin is refused too.
			resp = do(t, s, req{method: http.MethodOptions, path: "/v0/health", origin: origin,
				header: map[string]string{"Access-Control-Request-Method": "GET"}})
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("preflight status = %d, want 403", resp.StatusCode)
			}
		})
	}
}

func TestNoCORSOriginRefusesBrowsers(t *testing.T) {
	s, err := New(Config{Password: testPassword, Backend: newBackend()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	defer s.Shutdown(context.Background())
	r := authed("/v0/health")
	r.origin = testOrigin
	if resp := do(t, s, r); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if resp := do(t, s, authed("/v0/health")); resp.StatusCode != http.StatusOK {
		t.Fatalf("curl-style status = %d, want 200", resp.StatusCode)
	}
}

func TestHostRefused(t *testing.T) {
	s := start(t, newBackend(), nil)
	r := authed("/v0/health")
	r.host = "rebind.evil.example"
	if resp := do(t, s, r); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	port := s.Addr()[strings.LastIndex(s.Addr(), ":")+1:]
	r.host = "localhost:" + port
	if resp := do(t, s, r); resp.StatusCode != http.StatusOK {
		t.Fatalf("localhost status = %d, want 200", resp.StatusCode)
	}
}

func TestPreflight(t *testing.T) {
	s := start(t, newBackend(), nil)
	resp := do(t, s, req{method: http.MethodOptions, path: "/v0/workspaces", origin: testOrigin,
		header: map[string]string{
			"Access-Control-Request-Method":          "GET",
			"Access-Control-Request-Headers":         "authorization",
			"Access-Control-Request-Private-Network": "true",
		}})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	for k, want := range map[string]string{
		"Access-Control-Allow-Origin":          testOrigin,
		"Access-Control-Allow-Private-Network": "true",
	} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Errorf("Allow-Headers = %q", resp.Header.Get("Access-Control-Allow-Headers"))
	}
}

func TestAllowedOriginGetsCORSOn401(t *testing.T) {
	// The browser has to be able to read a 401 to say "password changed".
	s := start(t, newBackend(), nil)
	resp := do(t, s, req{path: "/v0/health", origin: testOrigin})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != testOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
}

func TestHealth(t *testing.T) {
	s := start(t, newBackend(), nil)
	r := authed("/v0/health")
	r.origin = testOrigin
	resp := do(t, s, r)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != testOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	var h Health
	if err := json.Unmarshal(body, &h); err != nil {
		t.Fatal(err)
	}
	if !h.OK || h.Auth.State != AuthOK || len(h.Workspaces) != 1 || h.Workspaces[0].State != WorkspaceConnected {
		t.Fatalf("health = %+v", h)
	}
	if h.Server.Listen != s.Addr() || h.Server.CORSOrigin != testOrigin || h.Server.Version != "test" {
		t.Errorf("server = %+v", h.Server)
	}
	if strings.Contains(string(body), testPassword) {
		t.Error("health body contains the password")
	}
}

func TestHealthNotOKWhenExpired(t *testing.T) {
	b := newBackend()
	b.auth = AuthStatus{State: AuthExpired, Error: "invalid_auth"}
	b.status[0].State = WorkspaceAuthExpired
	s := start(t, b, nil)
	var h Health
	json.NewDecoder(do(t, s, authed("/v0/health")).Body).Decode(&h)
	if h.OK {
		t.Fatalf("ok = true with expired auth")
	}
}

func TestWorkspaces(t *testing.T) {
	s := start(t, newBackend(), nil)
	resp := do(t, s, authed("/v0/workspaces"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got struct{ Workspaces []Workspace }
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got.Workspaces) != 1 || got.Workspaces[0].ID != "E017D49VC3F" || got.Workspaces[0].Name != "Shopify" {
		t.Fatalf("workspaces = %+v", got.Workspaces)
	}
}

func TestWorkspacesEmptyIsArray(t *testing.T) {
	b := newBackend()
	b.list = nil
	s := start(t, b, nil)
	body, _ := io.ReadAll(do(t, s, authed("/v0/workspaces")).Body)
	if strings.TrimSpace(string(body)) != `{"workspaces":[]}` {
		t.Fatalf("body = %s", body)
	}
}

func TestRefresh(t *testing.T) {
	b := newBackend()
	b.auth.State = AuthExpired
	s := start(t, b, nil)
	r := authed("/v0/auth/refresh")
	r.method = http.MethodPost
	resp := do(t, s, r)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var h Health
	json.NewDecoder(resp.Body).Decode(&h)
	if b.refreshes != 1 || h.Auth.State != AuthOK {
		t.Fatalf("refreshes = %d, auth = %+v", b.refreshes, h.Auth)
	}
	// GET is not a refresh.
	r.method = http.MethodGet
	if resp := do(t, s, r); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET refresh status = %d, want 404", resp.StatusCode)
	}
}

func TestBindsLoopbackOnly(t *testing.T) {
	s := start(t, newBackend(), nil)
	if !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
		t.Fatalf("addr = %s", s.Addr())
	}
}

func TestRequestLogHasNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	red := NewRedactor()
	red.Add(testPassword)
	s := start(t, newBackend(), red.Writer(&buf))
	do(t, s, authed("/v0/health?token=xoxc-123-456-789-abcdef"))
	do(t, s, req{path: "/v0/health", auth: true, user: Username, pass: testPassword + "x"})
	logs := buf.String()
	if !strings.Contains(logs, "GET /v0/health 200") || !strings.Contains(logs, "GET /v0/health 401") {
		t.Fatalf("logs = %q", logs)
	}
	for _, bad := range []string{testPassword, "xoxc-", "token="} {
		if strings.Contains(logs, bad) {
			t.Errorf("log contains %q: %q", bad, logs)
		}
	}
}

func TestNormalizeOrigin(t *testing.T) {
	good := map[string]string{
		"":                                     "",
		"https://workcenter.quick.shopify.io":  testOrigin,
		"https://workcenter.quick.shopify.io/": testOrigin,
		"HTTPS://Workcenter.Quick.Shopify.io":  testOrigin,
		"http://localhost:5173":                "http://localhost:5173",
	}
	for in, want := range good {
		got, err := NormalizeOrigin(in)
		if err != nil || got != want {
			t.Errorf("NormalizeOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"*", "workcenter.quick.shopify.io", "https://*.shopify.io", "https://a.example/path", "ftp://a.example", "https://u:p@a.example", "https://a.example?x=1"} {
		if got, err := NormalizeOrigin(in); err == nil {
			t.Errorf("NormalizeOrigin(%q) = %q, want error", in, got)
		}
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(Config{Backend: newBackend()}); err == nil {
		t.Error("empty password accepted")
	}
	if _, err := New(Config{Password: testPassword}); err == nil {
		t.Error("nil backend accepted")
	}
}
