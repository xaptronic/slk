package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gammons/slk/internal/server"
	slackclient "github.com/gammons/slk/internal/slack"
	"github.com/slack-go/slack"
)

// Fake credentials in the real shapes, so shape-based redaction is
// exercised too.
const (
	cachedToken  = "xoxc-cached-1111-2222"
	cachedCookie = "xoxd-cachedcookie%2Fabc%3D"
	liveToken    = "xoxc-live-3333-4444"
	liveCookie   = "xoxd-livecookie%2Bdef%3D"
)

type fakeServeSlack struct {
	mu        sync.Mutex
	cookieErr error
	// valid is the token auth.test accepts; anything else is invalid_auth.
	valid    string
	netErr   error
	connects []string
	saved    []slackclient.Token
	now      time.Time
}

func (f *fakeServeSlack) deps() serveDeps {
	return serveDeps{
		cookie: func() (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.cookieErr != nil {
				return "", f.cookieErr
			}
			return liveCookie, nil
		},
		desktopTokens: func() (map[string]string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.cookieErr != nil {
				return nil, f.cookieErr
			}
			return map[string]string{"E1": liveToken}, nil
		},
		mint: func(ctx context.Context, domain, cookie string) (string, error) {
			return "", errors.New("mint not expected")
		},
		save: func(t slackclient.Token) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.saved = append(f.saved, t)
			return nil
		},
		connect: func(ctx context.Context, tok slackclient.Token) (*slackclient.Client, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.connects = append(f.connects, tok.AccessToken)
			if f.netErr != nil {
				return nil, f.netErr
			}
			if tok.AccessToken != f.valid {
				// The shape slackclient.Client.Connect returns.
				return nil, fmt.Errorf("auth test failed: %w", slack.SlackErrorResponse{Err: "invalid_auth"})
			}
			return nil, nil
		},
		now: func() time.Time {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.now
		},
	}
}

func (f *fakeServeSlack) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func newTestSessions(t *testing.T, f *fakeServeSlack) (*serveSessions, *bytes.Buffer, *server.Redactor) {
	t.Helper()
	if f.now.IsZero() {
		f.now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	}
	var logs bytes.Buffer
	red := server.NewRedactor()
	logger := log.New(red.Writer(&logs), "", 0)
	tokens := []slackclient.Token{{
		AccessToken: cachedToken, Cookie: cachedCookie,
		Domain: "shopify", TeamID: "E1", TeamName: "Shopify",
	}}
	return newServeSessions(tokens, f.deps(), red, logger), &logs, red
}

func assertNoSecrets(t *testing.T, where, s string) {
	t.Helper()
	for _, secret := range []string{cachedToken, cachedCookie, liveToken, liveCookie, "cachedcookie", "livecookie", "3333-4444", "1111-2222"} {
		if strings.Contains(s, secret) {
			t.Errorf("%s contains %q: %s", where, secret, s)
		}
	}
}

func TestServeStartupReadsDesktopSession(t *testing.T) {
	f := &fakeServeSlack{valid: liveToken}
	s, logs, _ := newTestSessions(t, f)

	if auth, ws := s.Status(); auth.State != server.AuthStarting || ws[0].State != server.WorkspaceConnecting {
		t.Fatalf("before refresh: %+v %+v", auth, ws)
	}
	if err := s.Refresh(context.Background(), "startup", true); err != nil {
		t.Fatal(err)
	}
	auth, ws := s.Status()
	if auth.State != server.AuthOK || auth.Source != "desktop" || auth.Error != "" || auth.LastRefreshAt == nil {
		t.Fatalf("auth = %+v", auth)
	}
	if len(ws) != 1 || ws[0].ID != "E1" || ws[0].Name != "Shopify" || ws[0].State != server.WorkspaceConnected {
		t.Fatalf("workspaces = %+v", ws)
	}
	list := s.Workspaces()
	if len(list) != 1 || list[0].ID != "E1" || list[0].Name != "Shopify" || list[0].Domain != "shopify" {
		t.Fatalf("Workspaces() = %+v", list)
	}
	if len(f.saved) != 1 || f.saved[0].AccessToken != liveToken || f.saved[0].Cookie != liveCookie {
		t.Fatalf("saved = %+v", f.saved)
	}
	assertNoSecrets(t, "log", logs.String())
}

func TestServeFallsBackToCachedTokens(t *testing.T) {
	f := &fakeServeSlack{valid: cachedToken, cookieErr: errors.New("keyring locked")}
	s, _, _ := newTestSessions(t, f)
	s.Refresh(context.Background(), "startup", true)
	auth, _ := s.Status()
	if auth.State != server.AuthOK || auth.Source != "cached" || !strings.Contains(auth.Error, "keyring locked") {
		t.Fatalf("auth = %+v", auth)
	}
	if len(s.Workspaces()) != 1 {
		t.Fatal("cached-token workspace not listed")
	}
}

func TestServeExpiredThenRecoversFromDesktop(t *testing.T) {
	// Cached tokens expired and the desktop app is signed out.
	f := &fakeServeSlack{valid: liveToken, cookieErr: errors.New("no cookie")}
	s, logs, _ := newTestSessions(t, f)
	if err := s.Refresh(context.Background(), "startup", true); err == nil {
		t.Fatal("refresh succeeded with expired tokens")
	}
	auth, ws := s.Status()
	if auth.State != server.AuthExpired || ws[0].State != server.WorkspaceAuthExpired || ws[0].Error == "" {
		t.Fatalf("auth = %+v ws = %+v", auth, ws)
	}
	if len(s.Workspaces()) != 0 {
		t.Fatal("expired workspace listed as connected")
	}
	if _, ok := s.client("E1"); ok {
		t.Fatal("client() handed out an expired workspace")
	}

	// The person signs in to the desktop app; the next refresh picks the
	// live session up with no restart.
	f.mu.Lock()
	f.cookieErr = nil
	f.mu.Unlock()
	f.advance(time.Minute)
	if err := s.RefreshAuth(context.Background()); err != nil {
		t.Fatal(err)
	}
	auth, ws = s.Status()
	if auth.State != server.AuthOK || auth.Source != "desktop" || ws[0].State != server.WorkspaceConnected || ws[0].Error != "" {
		t.Fatalf("after re-read: auth = %+v ws = %+v", auth, ws)
	}
	if last := f.connects[len(f.connects)-1]; last != liveToken {
		t.Fatalf("reconnected with %q, want the live token", last)
	}
	assertNoSecrets(t, "log", logs.String())
}

func TestServeNetworkErrorIsNotAuthExpiry(t *testing.T) {
	f := &fakeServeSlack{valid: liveToken, netErr: errors.New("dial tcp: no route to host")}
	s, _, _ := newTestSessions(t, f)
	s.Refresh(context.Background(), "startup", true)
	auth, ws := s.Status()
	if auth.State != server.AuthError || ws[0].State != server.WorkspaceError || !strings.Contains(ws[0].Error, "no route") {
		t.Fatalf("auth = %+v ws = %+v", auth, ws)
	}
}

func TestServeRefreshCoalesces(t *testing.T) {
	f := &fakeServeSlack{valid: liveToken}
	s, _, _ := newTestSessions(t, f)
	s.Refresh(context.Background(), "startup", true)
	s.RefreshAuth(context.Background())
	s.RefreshAuth(context.Background())
	if len(f.connects) != 1 {
		t.Fatalf("connects = %d, want 1", len(f.connects))
	}
	f.advance(serveRefreshCoalesce)
	s.RefreshAuth(context.Background())
	if len(f.connects) != 2 {
		t.Fatalf("connects = %d, want 2 after the coalesce window", len(f.connects))
	}
}

func TestServeCheckDetectsExpiry(t *testing.T) {
	f := &fakeServeSlack{valid: liveToken}
	s, _, _ := newTestSessions(t, f)
	s.Refresh(context.Background(), "startup", true)

	// Slack revokes the session; the desktop app has a new one.
	f.mu.Lock()
	f.valid = "xoxc-rotated-5555"
	f.mu.Unlock()
	f.advance(time.Minute)
	s.check(context.Background())
	// check saw invalid_auth and started a background refresh, which
	// re-reads the desktop session (still the live token here, so it
	// stays expired: the point is that it ran).
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		n := len(f.connects)
		f.mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connects = %d, want a refresh after the failed check", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	for {
		auth, ws := s.Status()
		if auth.State == server.AuthExpired && ws[0].State == server.WorkspaceAuthExpired && auth.LastReason == "auth expired" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after check: auth = %+v ws = %+v", auth, ws)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestServeErrorsAreRedacted(t *testing.T) {
	f := &fakeServeSlack{valid: liveToken, netErr: fmt.Errorf("Post https://slack.com/api/auth.test?token=%s: cookie d=%s: EOF", liveToken, liveCookie)}
	s, logs, _ := newTestSessions(t, f)
	s.Refresh(context.Background(), "startup", true)
	auth, ws := s.Status()
	assertNoSecrets(t, "workspace error", ws[0].Error)
	assertNoSecrets(t, "auth error", auth.Error)
	assertNoSecrets(t, "log", logs.String())
	if !strings.Contains(ws[0].Error, server.Redacted) {
		t.Fatalf("error not redacted: %q", ws[0].Error)
	}
}

func TestIsSlackAuthError(t *testing.T) {
	for _, code := range []string{"invalid_auth", "not_authed", "token_revoked", "token_expired", "account_inactive"} {
		if !isSlackAuthError(fmt.Errorf("wrapped: %w", slack.SlackErrorResponse{Err: code})) {
			t.Errorf("%s not treated as auth error", code)
		}
	}
	for _, err := range []error{nil, errors.New("invalid_auth"), slack.SlackErrorResponse{Err: "ratelimited"}, context.DeadlineExceeded} {
		if isSlackAuthError(err) {
			t.Errorf("%v treated as auth error", err)
		}
	}
}
