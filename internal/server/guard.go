package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// NormalizeOrigin validates a --cors value and returns it in the form a
// browser sends in the Origin header: scheme://host[:port], lower-case, no
// path and no trailing slash. Empty stays empty (no browser origin
// allowed).
func NormalizeOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return "", fmt.Errorf("--cors %q: %w", raw, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("--cors %q: scheme must be http or https", raw)
	}
	if u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("--cors %q: want exactly one origin like https://workcenter.quick.shopify.io", raw)
	}
	if strings.Contains(u.Host, "*") {
		return "", fmt.Errorf("--cors %q: wildcards are not allowed", raw)
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
}

// guard applies, in order: the Host check (DNS rebinding), the exact
// Origin check, CORS (including preflight, which carries no credentials),
// and HTTP basic auth. Nothing reaches a route, or even learns whether a
// route exists, without passing all four.
func (s *Server) guard(next http.Handler) http.Handler {
	wantUser := sha256.Sum256([]byte(Username))
	wantPass := sha256.Sum256([]byte(s.cfg.Password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A page on evil.example can resolve its own hostname to
		// 127.0.0.1 and then talk to us "same-origin", with no Origin
		// header on GETs. Requiring a loopback Host defeats that.
		if s.allowedHosts != nil && !s.allowedHosts[strings.ToLower(r.Host)] {
			writeError(w, http.StatusForbidden, "forbidden_host", "Host must be 127.0.0.1 or localhost")
			return
		}

		// Any Origin header, including "null" from sandboxed iframes,
		// must match --cors exactly. No Origin means a non-browser
		// client (curl), which still has to authenticate below.
		if origin, present := r.Header["Origin"]; present {
			if s.cfg.Origin == "" || len(origin) != 1 || origin[0] != s.cfg.Origin {
				writeError(w, http.StatusForbidden, "forbidden_origin", "this origin is not allowed; start slk serve with --cors <origin>")
				return
			}
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", s.cfg.Origin)
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
				// Chrome's Private Network Access: a public https page
				// calling 127.0.0.1 must be explicitly allowed.
				if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
					h.Set("Access-Control-Allow-Private-Network", "true")
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		user, pass, ok := r.BasicAuth()
		gotUser := sha256.Sum256([]byte(user))
		gotPass := sha256.Sum256([]byte(pass))
		userOK := subtle.ConstantTimeCompare(gotUser[:], wantUser[:])
		passOK := subtle.ConstantTimeCompare(gotPass[:], wantPass[:])
		if !ok || userOK&passOK != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="slk serve", charset="UTF-8"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or wrong password (it changes every time slk serve restarts)")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// logRequests writes one line per request: method, path (never the query
// string or headers), status and duration.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.cfg.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		ms := float64(s.cfg.Now().Sub(start).Microseconds()) / 1000
		s.cfg.Logger.Printf("%s %s %d %.1fms", r.Method, r.URL.Path, rec.status, ms)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush keeps streaming responses (WC-4) working through the recorder.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// ErrWeakPassword is returned by CheckPassword for a too-short override.
var ErrWeakPassword = errors.New("SLK_SERVER_PASSWORD must be at least 16 characters")

// CheckPassword validates a SLK_SERVER_PASSWORD override.
func CheckPassword(p string) error {
	if len(p) < 16 {
		return ErrWeakPassword
	}
	return nil
}
