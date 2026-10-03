package server

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// GeneratePassword returns a fresh random password: 24 bytes from
// crypto/rand, base64url without padding (32 characters).
func GeneratePassword() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on supported platforms; refusing to
		// start beats starting with a guessable password.
		panic("slk serve: crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// slackSecretRE matches Slack credential shapes: xoxc-/xoxd-/xoxb-/xoxp-
// tokens and the d cookie (xoxd-...), raw or URL-encoded.
var slackSecretRE = regexp.MustCompile(`xox[a-z]-[A-Za-z0-9%._~+/=\-]+`)

// Redacted replaces a scrubbed secret.
const Redacted = "[redacted]"

// Redactor scrubs known secrets (the server password, every xoxc token and
// d cookie slk serve has loaded) plus anything shaped like a Slack token
// from text before it is logged. Secrets can be added at any time, e.g.
// after a token refresh.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

// NewRedactor returns an empty Redactor.
func NewRedactor() *Redactor { return &Redactor{} }

// Add registers secrets. Empty strings are ignored. Each secret is also
// registered in its URL-encoded forms, which is how a d cookie appears in
// headers and URLs.
func (r *Redactor) Add(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[string]bool, len(r.secrets))
	for _, s := range r.secrets {
		seen[s] = true
	}
	for _, s := range secrets {
		if s == "" {
			continue
		}
		for _, v := range []string{s, url.QueryEscape(s), url.PathEscape(s)} {
			if v != "" && !seen[v] {
				seen[v] = true
				r.secrets = append(r.secrets, v)
			}
		}
		if dec, err := url.QueryUnescape(s); err == nil && dec != "" && !seen[dec] {
			seen[dec] = true
			r.secrets = append(r.secrets, dec)
		}
	}
	// Longest first, so a secret that contains another is replaced whole.
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
}

// String returns s with every secret replaced by Redacted.
func (r *Redactor) String(s string) string {
	if r != nil {
		r.mu.RLock()
		for _, secret := range r.secrets {
			if strings.Contains(s, secret) {
				s = strings.ReplaceAll(s, secret, Redacted)
			}
		}
		r.mu.RUnlock()
	}
	return slackSecretRE.ReplaceAllStringFunc(s, func(m string) string {
		return m[:5] + Redacted
	})
}

// Writer wraps w so everything written through it is redacted first. The
// log package issues one Write per line, so a secret is never split across
// calls when this backs a *log.Logger.
func (r *Redactor) Writer(w io.Writer) io.Writer {
	return &redactingWriter{r: r, w: w}
}

type redactingWriter struct {
	r *Redactor
	w io.Writer
}

func (rw *redactingWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(rw.w, rw.r.String(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
