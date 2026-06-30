package creds

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnquote(t *testing.T) {
	if got := Unquote(`"x"`); got != "x" {
		t.Errorf("Unquote(\"x\") = %q, want x", got)
	}
	if got := Unquote(`'y'`); got != "y" {
		t.Errorf("Unquote('y') = %q, want y", got)
	}
	if got := Unquote(`z`); got != "z" {
		t.Errorf("Unquote(z) = %q, want z", got)
	}
}

func TestLoadFull(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	yaml := `jwt: eyJhbGci
header: "X-Api-Key: abc"
cookie: session=deadbeef
login:
  url: http://app/login
  method: post
  username_field: uid
  password_field: passw
  username: admin
  password: admin
  success: Logout
ssh:
  host: 10.0.0.1
  port: 2222
  user: root
  password: toor
  key: /root/.ssh/id_rsa
windows:
  host: 10.0.0.2
  user: admin
  password: p@ss
  domain: corp
  hash: deadbeef
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	c := Load(path)
	if c == nil {
		t.Fatal("Load returned nil")
	}
	if c.JWT == nil || *c.JWT != "eyJhbGci" {
		t.Errorf("JWT = %v, want eyJhbGci", c.JWT)
	}
	if c.Login == nil || c.Login.Method != "POST" || c.Login.URL != "http://app/login" || c.Login.Username != "admin" {
		t.Errorf("Login fields incorrect: %+v", c.Login)
	}
	if c.SSH == nil || c.SSH.Port != "2222" || c.SSH.User != "root" {
		t.Errorf("SSH fields incorrect: %+v", c.SSH)
	}
	if c.Win == nil || c.Win.Domain != "corp" || c.Win.Hash != "deadbeef" {
		t.Errorf("Win fields incorrect: %+v", c.Win)
	}
	ah := c.AuthHeader()
	if ah == nil || *ah != "X-Api-Key: abc" {
		t.Errorf("AuthHeader precedence wrong: %v", ah)
	}
}

func TestLoadMissing(t *testing.T) {
	if c := Load(filepath.Join(t.TempDir(), "missing.yaml")); c != nil {
		t.Errorf("Load missing file should return nil, got %+v", c)
	}
}

func TestAuthHeaderPrecedence(t *testing.T) {
	c := &Creds{JWT: str("tok"), Cookie: str("c=1")}
	if got := *c.AuthHeader(); got != "Authorization: Bearer tok" {
		t.Errorf("AuthHeader = %q, want Authorization: Bearer tok", got)
	}
	c = &Creds{Cookie: str("c=1")}
	if got := *c.AuthHeader(); got != "Cookie: c=1" {
		t.Errorf("AuthHeader = %q, want Cookie: c=1", got)
	}
	if c := (&Creds{}).AuthHeader(); c != nil {
		t.Errorf("empty Creds.AuthHeader should be nil, got %v", *c)
	}
}

func TestHostInstruction(t *testing.T) {
	c := &Creds{
		SSH: &Ssh{Host: "10.0.0.1", Port: "22", User: "root", Password: "root"},
	}
	s := c.HostInstruction()
	if s == nil || !strings.Contains(*s, "SSH ACCESS") {
		t.Errorf("HostInstruction should contain SSH ACCESS, got %v", s)
	}
}

func TestLoginInstruction(t *testing.T) {
	c := &Creds{Login: &Login{Method: "POST", URL: "http://x/login", UsernameField: "u", PasswordField: "p", Username: "a", Password: "b", Success: "s"}}
	s := c.LoginInstruction()
	if s == nil || !strings.Contains(*s, "AUTHENTICATE FIRST") {
		t.Errorf("LoginInstruction missing directive, got %v", s)
	}
}

func TestLoginWithCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	}))
	defer server.Close()

	l := &Login{URL: server.URL, Method: "POST", UsernameField: "u", PasswordField: "p", Username: "a", Password: "b", Success: "ok"}
	auth, note, err := DoLogin(t.Context(), l)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if auth != "Cookie: session=abc123" {
		t.Errorf("auth = %q, want Cookie: session=abc123", auth)
	}
	if note == "" {
		t.Errorf("expected non-empty note")
	}
}

func TestLoginWithJSONToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"access_token":"tokxyz"}`)
	}))
	defer server.Close()

	l := &Login{URL: server.URL, Method: "POST", UsernameField: "u", PasswordField: "p", Username: "a", Password: "b"}
	auth, note, err := DoLogin(t.Context(), l)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if auth != "Authorization: Bearer tokxyz" {
		t.Errorf("auth = %q, want Authorization: Bearer tokxyz", auth)
	}
	if note == "" {
		t.Errorf("expected non-empty note")
	}
}

func str(s string) *string { return &s }
