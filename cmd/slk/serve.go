package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gammons/slk/internal/config"
	"github.com/gammons/slk/internal/debuglog"
	"github.com/gammons/slk/internal/server"
	slackclient "github.com/gammons/slk/internal/slack"
	"github.com/gammons/slk/internal/slackdesktop"
	"github.com/slack-go/slack"
)

// `slk serve`: a loopback HTTP API over the configured workspaces, for
// Workcenter. HTTP, auth and CORS live in internal/server; this file owns
// the Slack side (tokens, desktop session refresh, connection state) so it
// can reuse cmd/slk's helpers.

const (
	serveDefaultPort = 4097
	// serveCheckEvery is how often a healthy workspace is re-checked with
	// auth.test, which is how an expired session is noticed between
	// requests.
	serveCheckEvery = 5 * time.Minute
	// serveRetryMin/Max bound the backoff while any workspace is down.
	serveRetryMin = time.Minute
	serveRetryMax = 10 * time.Minute
	// serveRefreshCoalesce collapses refresh requests that arrive right
	// after one finished (several failing calls, a double-clicked button).
	serveRefreshCoalesce = 10 * time.Second
	serveConnectTimeout  = 20 * time.Second
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	port := fs.Int("port", serveDefaultPort, "port to listen on at 127.0.0.1")
	cors := fs.String("cors", "", "the one browser origin allowed to call the server, e.g. https://workcenter.quick.shopify.io")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: slk serve [--port %d] [--cors <origin>]\n\n", serveDefaultPort)
		fmt.Fprintln(os.Stderr, "Serve the configured workspaces over HTTP on 127.0.0.1 for Workcenter.")
		fmt.Fprintln(os.Stderr, "Every request needs HTTP basic auth: user \"slk\" and the password printed at startup")
		fmt.Fprintln(os.Stderr, "(set SLK_SERVER_PASSWORD to choose it). Requests from any Origin other than --cors are refused.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("serve: unexpected argument %q", fs.Arg(0))
	}
	origin, err := server.NormalizeOrigin(*cors)
	if err != nil {
		return err
	}

	password, fromEnv := os.LookupEnv("SLK_SERVER_PASSWORD")
	if fromEnv {
		if err := server.CheckPassword(password); err != nil {
			return err
		}
	} else {
		password = server.GeneratePassword()
	}

	// Every log line from here on is redacted: the password, every token
	// and cookie we load, and anything shaped like a Slack token. Without
	// SLK_DEBUG, main routed the stdlib logger to io.Discard for the TUI's
	// sake; a server should show its warnings, so send them to stderr.
	redactor := server.NewRedactor()
	redactor.Add(password)
	var logDest io.Writer = os.Stderr
	if debuglog.Enabled() {
		logDest = log.Writer()
	}
	log.SetOutput(redactor.Writer(logDest))
	log.SetFlags(log.LstdFlags)
	logger := log.New(redactor.Writer(os.Stderr), "slk serve: ", log.LstdFlags)

	tokenStore := slackclient.NewTokenStore(filepath.Join(xdgData(), "tokens"))
	tokens, err := tokenStore.List()
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return errors.New("no workspaces configured: run `slk --add-workspace` first")
	}
	cfg, err := config.Load(filepath.Join(xdgConfig(), "config.toml"))
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	ordered := config.OrderTokens(tokens, cfg)
	tokens = tokens[:0]
	for _, ot := range ordered {
		tokens = append(tokens, ot.Token)
	}

	sessions := newServeSessions(tokens, serveDeps{
		cookie:        slackdesktop.Cookie,
		desktopTokens: slackdesktop.Tokens,
		mint:          slackclient.MintToken,
		save:          tokenStore.Save,
		connect: func(ctx context.Context, tok slackclient.Token) (*slackclient.Client, error) {
			client := slackclient.NewClient(tok.AccessToken, tok.Cookie)
			seedVersionTS(client.Envelope(), cfg, tok.TeamID)
			return client, client.Connect(ctx)
		},
		now: time.Now,
	}, redactor, logger)

	srv, err := server.New(server.Config{
		Port:     *port,
		Origin:   origin,
		Password: password,
		Version:  version,
		Backend:  sessions,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return fmt.Errorf("listen on 127.0.0.1:%d: %w", *port, err)
	}

	// The banner is the only place the password is ever printed. It goes
	// straight to stdout, not through the logger (which would redact it).
	fmt.Printf("slk serve %s listening on %s\n", version, srv.URL())
	if origin != "" {
		fmt.Printf("  allowed origin: %s\n", origin)
	} else {
		fmt.Println("  allowed origin: none (pass --cors <origin> to allow a browser page)")
	}
	fmt.Printf("  username:       %s\n", server.Username)
	if fromEnv {
		fmt.Println("  password:       from SLK_SERVER_PASSWORD")
	} else {
		fmt.Printf("  password:       %s\n", password)
		fmt.Println("  (a new password every time slk serve starts; set SLK_SERVER_PASSWORD to keep one)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		sessions.Refresh(ctx, "startup", true)
		sessions.monitor(ctx)
	}()

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Printf("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

// serveDeps are the Slack-side operations, injected for tests.
type serveDeps struct {
	cookie        func() (string, error)
	desktopTokens func() (map[string]string, error)
	mint          func(ctx context.Context, domain, cookie string) (string, error)
	save          func(slackclient.Token) error
	// connect builds a client for tok and runs auth.test. It may return a
	// non-nil client together with an error.
	connect func(ctx context.Context, tok slackclient.Token) (*slackclient.Client, error)
	now     func() time.Time
}

type serveWorkspace struct {
	// token holds the xoxc token and d cookie. Never serialized, never
	// logged; only IDs and names leave this struct.
	token     slackclient.Token
	client    *slackclient.Client
	userID    string
	domain    string
	state     string
	err       string
	checkedAt time.Time
}

// serveSessions is the server.Backend: the configured workspaces, their
// clients and connection state, and the desktop-session refresh.
type serveSessions struct {
	deps     serveDeps
	redactor *server.Redactor
	logger   *log.Logger

	// refreshMu serializes Refresh; mu guards the fields below.
	refreshMu sync.Mutex
	mu        sync.RWMutex
	order     []string
	byID      map[string]*serveWorkspace
	auth      server.AuthStatus
	refreshed time.Time
}

func newServeSessions(tokens []slackclient.Token, deps serveDeps, redactor *server.Redactor, logger *log.Logger) *serveSessions {
	s := &serveSessions{
		deps:     deps,
		redactor: redactor,
		logger:   logger,
		byID:     make(map[string]*serveWorkspace, len(tokens)),
		auth:     server.AuthStatus{State: server.AuthStarting},
	}
	for _, tok := range tokens {
		redactor.Add(tok.AccessToken, tok.Cookie)
		s.order = append(s.order, tok.TeamID)
		s.byID[tok.TeamID] = &serveWorkspace{token: tok, state: server.WorkspaceConnecting}
	}
	return s
}

// Status implements server.Backend.
func (s *serveSessions) Status() (server.AuthStatus, []server.WorkspaceStatus) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]server.WorkspaceStatus, 0, len(s.order))
	for _, id := range s.order {
		w := s.byID[id]
		st := server.WorkspaceStatus{
			ID:     id,
			Name:   w.token.TeamName,
			State:  w.state,
			UserID: w.userID,
			Error:  w.err,
		}
		if !w.checkedAt.IsZero() {
			t := w.checkedAt.UTC()
			st.LastCheckedAt = &t
		}
		out = append(out, st)
	}
	return s.auth, out
}

// Workspaces implements server.Backend.
func (s *serveSessions) Workspaces() []server.Workspace {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []server.Workspace
	for _, id := range s.order {
		w := s.byID[id]
		if w.state != server.WorkspaceConnected {
			continue
		}
		out = append(out, server.Workspace{ID: id, Name: w.token.TeamName, Domain: w.domain, UserID: w.userID})
	}
	return out
}

// RefreshAuth implements server.Backend.
func (s *serveSessions) RefreshAuth(ctx context.Context) error {
	return s.Refresh(ctx, "requested", false)
}

// client returns a connected workspace's client, for the endpoints that
// call Slack (WC-3). A call that fails with an auth error should call
// authFailed so the desktop session is re-read.
func (s *serveSessions) client(teamID string) (*slackclient.Client, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w := s.byID[teamID]
	if w == nil || w.state != server.WorkspaceConnected || w.client == nil {
		return nil, false
	}
	return w.client, true
}

// authFailed records that a Slack call for teamID was rejected as
// unauthenticated and re-reads the desktop session in the background.
func (s *serveSessions) authFailed(ctx context.Context, teamID string, err error) {
	s.mu.Lock()
	if w := s.byID[teamID]; w != nil {
		w.state = server.WorkspaceAuthExpired
		w.err = s.errText(err)
		w.checkedAt = s.deps.now()
	}
	s.auth.State = server.AuthExpired
	s.mu.Unlock()
	go s.Refresh(context.WithoutCancel(ctx), "auth expired", false)
}

// Refresh re-reads the live Slack desktop session (cookie and tokens),
// saves any new tokens to the token store, and reconnects every
// workspace. Unless force is set, a refresh that finished within
// serveRefreshCoalesce is reused instead of running again.
func (s *serveSessions) Refresh(ctx context.Context, reason string, force bool) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	s.mu.Lock()
	if !force && !s.refreshed.IsZero() && s.deps.now().Sub(s.refreshed) < serveRefreshCoalesce {
		state, errText := s.auth.State, s.auth.Error
		s.mu.Unlock()
		if state != server.AuthOK {
			return errors.New(errText)
		}
		return nil
	}
	prevState := s.auth.State
	s.auth.State = server.AuthRefreshing
	tokens := make([]slackclient.Token, 0, len(s.order))
	for _, id := range s.order {
		tokens = append(tokens, s.byID[id].token)
	}
	s.mu.Unlock()

	// Wrap the cookie reader so we learn whether the live desktop session
	// was readable, and register fresh secrets with the redactor before
	// anything can log them.
	var cookieErr error
	cookieFn := func() (string, error) {
		c, err := s.deps.cookie()
		cookieErr = err
		if err == nil {
			s.redactor.Add(c)
		}
		return c, err
	}
	desktopFn := func() (map[string]string, error) {
		m, err := s.deps.desktopTokens()
		for _, v := range m {
			s.redactor.Add(v)
		}
		return m, err
	}
	mintFn := func(ctx context.Context, domain, cookie string) (string, error) {
		t, err := s.deps.mint(ctx, domain, cookie)
		s.redactor.Add(t)
		return t, err
	}
	fresh := remintTokens(ctx, tokens, cookieFn, desktopFn, mintFn, s.deps.save)

	type result struct {
		w   serveWorkspace
		err error
	}
	results := make([]result, len(fresh))
	var wg sync.WaitGroup
	for i, tok := range fresh {
		wg.Add(1)
		go func(i int, tok slackclient.Token) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, serveConnectTimeout)
			defer cancel()
			client, err := s.connectBounded(cctx, tok)
			r := serveWorkspace{token: tok, checkedAt: s.deps.now()}
			if err == nil && client != nil {
				r.client = client
				r.userID = client.UserID()
				r.domain = client.TeamSubdomain()
			}
			if r.domain == "" {
				r.domain = tok.Domain
			}
			results[i] = result{w: r, err: err}
		}(i, tok)
	}
	wg.Wait()

	now := s.deps.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	connected, expired := 0, 0
	for _, r := range results {
		w := r.w
		switch {
		case r.err == nil:
			w.state = server.WorkspaceConnected
			connected++
		case isSlackAuthError(r.err):
			w.state = server.WorkspaceAuthExpired
			w.err = s.errText(r.err)
			expired++
		default:
			w.state = server.WorkspaceError
			w.err = s.errText(r.err)
		}
		s.byID[w.token.TeamID] = &w
		if r.err != nil {
			s.logger.Printf("%s (%s): %s", w.token.TeamName, w.token.TeamID, w.err)
		} else {
			s.logger.Printf("connected to %s (%s) as %s", w.token.TeamName, w.token.TeamID, w.userID)
		}
	}

	source := "desktop"
	if cookieErr != nil {
		source = "cached"
	}
	auth := server.AuthStatus{Source: source, LastReason: reason}
	t := now.UTC()
	auth.LastRefreshAt = &t
	switch {
	case expired > 0:
		auth.State = server.AuthExpired
		auth.Error = "Slack rejected the session; sign in to the Slack desktop app, then POST /v0/auth/refresh"
		if cookieErr != nil {
			auth.Error = "Slack rejected the cached session and the desktop session could not be read: " + s.errText(cookieErr)
		}
	case connected == len(results) && connected > 0:
		auth.State = server.AuthOK
	default:
		auth.State = server.AuthError
		auth.Error = "could not reach Slack for every workspace; see workspaces[].error"
	}
	if auth.State == server.AuthOK && cookieErr != nil {
		// Working on cached tokens: fine until they expire.
		auth.Error = "using cached tokens; the desktop session could not be read: " + s.errText(cookieErr)
	}
	s.auth = auth
	s.refreshed = now
	if auth.State != prevState {
		s.logger.Printf("auth %s (source %s, reason %s)", auth.State, source, reason)
	}
	if auth.State != server.AuthOK {
		return errors.New(auth.Error)
	}
	return nil
}

// connectBounded runs deps.connect but gives up when ctx ends. auth.test
// in slack-go takes no context, so a wedged connection would otherwise pin
// the refresh (and the lock) indefinitely.
func (s *serveSessions) connectBounded(ctx context.Context, tok slackclient.Token) (*slackclient.Client, error) {
	type res struct {
		c   *slackclient.Client
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := s.deps.connect(ctx, tok)
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("connecting to Slack: %w", ctx.Err())
	}
}

// check re-runs auth.test for every connected workspace and refreshes the
// session if any is rejected.
func (s *serveSessions) check(ctx context.Context) {
	s.mu.RLock()
	var tokens []slackclient.Token
	for _, id := range s.order {
		if w := s.byID[id]; w.state == server.WorkspaceConnected {
			tokens = append(tokens, w.token)
		}
	}
	s.mu.RUnlock()
	for _, tok := range tokens {
		cctx, cancel := context.WithTimeout(ctx, serveConnectTimeout)
		_, err := s.connectBounded(cctx, tok)
		cancel()
		now := s.deps.now()
		if err != nil && isSlackAuthError(err) {
			s.logger.Printf("%s: session expired, re-reading the Slack desktop session", tok.TeamName)
			s.authFailed(ctx, tok.TeamID, err)
			return
		}
		s.mu.Lock()
		if w := s.byID[tok.TeamID]; w != nil && w.state == server.WorkspaceConnected {
			w.checkedAt = now
			if err != nil {
				w.state = server.WorkspaceError
				w.err = s.errText(err)
			}
		}
		s.mu.Unlock()
	}
}

// monitor keeps connection state current: healthy workspaces are checked
// every serveCheckEvery; while any is down, the desktop session is re-read
// with backoff.
func (s *serveSessions) monitor(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	backoff := serveRetryMin
	lastCheck := s.deps.now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now := s.deps.now()
		s.mu.RLock()
		healthy := s.auth.State == server.AuthOK
		since := now.Sub(s.refreshed)
		s.mu.RUnlock()
		if !healthy {
			if since >= backoff {
				if s.Refresh(ctx, "retry", false) == nil {
					backoff = serveRetryMin
				} else if backoff *= 2; backoff > serveRetryMax {
					backoff = serveRetryMax
				}
				lastCheck = s.deps.now()
			}
			continue
		}
		backoff = serveRetryMin
		if now.Sub(lastCheck) >= serveCheckEvery {
			s.check(ctx)
			lastCheck = s.deps.now()
		}
	}
}

// errText turns an error into a short, redacted message safe for logs and
// the health endpoint.
func (s *serveSessions) errText(err error) string {
	if err == nil {
		return ""
	}
	msg := s.redactor.String(err.Error())
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return msg
}

// isSlackAuthError reports whether err means the session itself is no
// longer valid (as opposed to the network or Slack being down).
func isSlackAuthError(err error) bool {
	var se slack.SlackErrorResponse
	if errors.As(err, &se) {
		switch se.Err {
		case "invalid_auth", "not_authed", "token_revoked", "token_expired", "account_inactive":
			return true
		}
	}
	return false
}
