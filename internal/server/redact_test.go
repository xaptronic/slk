package server

import (
	"bytes"
	"log"
	"net/url"
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	a, b := GeneratePassword(), GeneratePassword()
	if a == b {
		t.Fatal("two runs produced the same password")
	}
	if len(a) != 32 || CheckPassword(a) != nil {
		t.Fatalf("password %q: len %d", a, len(a))
	}
	if strings.ContainsAny(a, ":+/= ") {
		t.Fatalf("password %q has characters that need quoting", a)
	}
}

func TestCheckPassword(t *testing.T) {
	if CheckPassword("short") == nil {
		t.Error("short password accepted")
	}
	if err := CheckPassword("sixteen-chars-ok"); err != nil {
		t.Error(err)
	}
}

func TestRedactorKnownSecrets(t *testing.T) {
	// Fake values in the shapes slk handles: a d cookie with characters
	// that URL-encode, and an xoxc token.
	cookie := "xoxd-AbC%2Fdef%2Bghi%3D%3D"
	decodedCookie, _ := url.QueryUnescape(cookie)
	token := "xoxc-1111-2222-3333-abcdef"
	password := "Zm9vYmFyYmF6cXV4cXV1eGNvcmdl"

	r := NewRedactor()
	r.Add(cookie, token, password, "")

	in := strings.Join([]string{
		"cookie=" + cookie,
		"decoded=" + decodedCookie,
		"query=" + url.QueryEscape(decodedCookie),
		"token=" + token,
		"Authorization: Basic " + password,
	}, " ")
	out := r.String(in)
	for _, secret := range []string{cookie, decodedCookie, token, password, "AbC", "abcdef"} {
		if strings.Contains(out, secret) {
			t.Errorf("redacted output still contains %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, Redacted) {
		t.Errorf("nothing redacted: %s", out)
	}
}

func TestRedactorTokenShapes(t *testing.T) {
	// Not registered: caught by shape alone.
	r := NewRedactor()
	for _, s := range []string{
		"xoxc-9999-8888-7777-ffff",
		"xoxd-zzz%2Fyyy%3D",
		"xoxb-123-abc",
		"xoxp-123-abc",
	} {
		out := r.String("before " + s + " after")
		if strings.Contains(out, s[5:]) {
			t.Errorf("%q not redacted: %s", s, out)
		}
		if !strings.HasPrefix(out, "before ") || !strings.HasSuffix(out, " after") {
			t.Errorf("surrounding text damaged: %q", out)
		}
	}
	var nilR *Redactor
	if out := nilR.String("xoxc-1-2"); strings.Contains(out, "1-2") {
		t.Errorf("nil redactor leaked: %s", out)
	}
}

func TestRedactorAddLater(t *testing.T) {
	// Tokens are re-minted after startup; later Adds must take effect.
	var buf bytes.Buffer
	r := NewRedactor()
	l := log.New(r.Writer(&buf), "", 0)
	secret := "not-shaped-like-a-token-1234"
	r.Add(secret)
	l.Printf("value %s", secret)
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("log leaked: %s", buf.String())
	}
}
