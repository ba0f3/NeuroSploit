package creds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Login describes an HTTP form-based login flow.
type Login struct {
	URL           string `json:"url"`
	Method        string `json:"method"`
	UsernameField string `json:"username_field"`
	PasswordField string `json:"password_field"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	Success       string `json:"success"`
}

// Ssh holds SSH credentials for Linux host testing.
type Ssh struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Key      string `json:"key"`
}

// Win holds Windows / Active Directory credentials.
type Win struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
	Hash     string `json:"hash"`
}

// Creds is the loaded credential set from creds.yaml.
type Creds struct {
	JWT    *string `json:"jwt,omitempty"`
	Header *string `json:"header,omitempty"`
	Cookie *string `json:"cookie,omitempty"`
	Login  *Login  `json:"login,omitempty"`
	SSH    *Ssh    `json:"ssh,omitempty"`
	Win    *Win    `json:"win,omitempty"`
}

// Load reads a creds.yaml file and returns the parsed credential set.
// Returns nil if the file is missing or contains no recognizable credential block.
func Load(path string) *Creds {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var c Creds
	login := Login{Method: "POST"}
	ssh := Ssh{Port: "22"}
	win := Win{}
	haveLogin, haveSSH, haveWin := false, false, false
	block := ""
	for _, raw := range strings.Split(string(text), "\n") {
		line := strings.Split(raw, "#")[0]
		if strings.TrimSpace(line) == "" {
			continue
		}
		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := Unquote(strings.TrimSpace(line[idx+1:]))
		if v == "" && !indented {
			switch k {
			case "login":
				haveLogin = true
				block = "login"
			case "ssh":
				haveSSH = true
				block = "ssh"
			case "windows", "win", "ad":
				haveWin = true
				block = "windows"
			default:
				block = ""
			}
			continue
		}
		if indented {
			switch block {
			case "login":
				switch k {
				case "url":
					login.URL = v
				case "method":
					login.Method = strings.ToUpper(v)
				case "username_field":
					login.UsernameField = v
				case "password_field":
					login.PasswordField = v
				case "username", "user":
					login.Username = v
				case "password", "pass":
					login.Password = v
				case "success":
					login.Success = v
				}
			case "ssh":
				switch k {
				case "host", "ip":
					ssh.Host = v
				case "port":
					ssh.Port = v
				case "user", "username":
					ssh.User = v
				case "password", "pass":
					ssh.Password = v
				case "key", "keyfile", "identity":
					ssh.Key = v
				}
			case "windows":
				switch k {
				case "host", "ip":
					win.Host = v
				case "user", "username":
					win.User = v
				case "password", "pass":
					win.Password = v
				case "domain":
					win.Domain = v
				case "hash", "ntlm":
					win.Hash = v
				}
			}
			continue
		}
		block = ""
		switch k {
		case "jwt", "token":
			c.JWT = &v
		case "header":
			c.Header = &v
		case "cookie":
			c.Cookie = &v
		}
	}
	if haveLogin && login.URL != "" {
		c.Login = &login
	}
	if haveSSH && ssh.Host != "" {
		c.SSH = &ssh
	}
	if haveWin && win.Host != "" {
		c.Win = &win
	}
	if c.JWT == nil && c.Header == nil && c.Cookie == nil && c.Login == nil && c.SSH == nil && c.Win == nil {
		return nil
	}
	return &c
}

// AuthHeader returns the request header line to use, or nil if none configured.
func (c *Creds) AuthHeader() *string {
	if c == nil {
		return nil
	}
	if c.Header != nil {
		return c.Header
	}
	if c.JWT != nil {
		s := fmt.Sprintf("Authorization: Bearer %s", *c.JWT)
		return &s
	}
	if c.Cookie != nil {
		s := fmt.Sprintf("Cookie: %s", *c.Cookie)
		return &s
	}
	return nil
}

// HostInstruction returns a directive describing host credentials available to agents.
func (c *Creds) HostInstruction() *string {
	if c == nil {
		return nil
	}
	var s strings.Builder
	if c.SSH != nil {
		auth := "password (provided)"
		if c.SSH.Key != "" {
			auth = fmt.Sprintf("private key %s", c.SSH.Key)
		}
		fmt.Fprintf(&s,
			"SSH ACCESS (Linux): host %s:%s as user '%s' via %s. Use `ssh`/`sshpass` to run enumeration and privilege-escalation checks on the host.\n",
			c.SSH.Host, c.SSH.Port, c.SSH.User, auth)
	}
	if c.Win != nil {
		auth := "password"
		if c.Win.Hash != "" {
			auth = "NTLM hash (pass-the-hash)"
		}
		domain := "(workgroup)"
		if c.Win.Domain != "" {
			domain = c.Win.Domain
		}
		fmt.Fprintf(&s,
			"WINDOWS/AD ACCESS: host %s domain '%s' as user '%s' via %s. Use tools like crackmapexec/netexec, impacket, evil-winrm, bloodhound-python for host and AD checks.\n",
			c.Win.Host, domain, c.Win.User, auth)
	}
	if s.Len() == 0 {
		return nil
	}
	out := s.String()
	return &out
}

// LoginInstruction returns a directive instructing the agent to authenticate first.
func (c *Creds) LoginInstruction() *string {
	if c == nil || c.Login == nil {
		return nil
	}
	l := c.Login
	s := fmt.Sprintf("AUTHENTICATE FIRST: %s %s with %s=%s and %s=%s; capture the session cookie/token from the response (success indicator: \"%s\") and reuse it on every subsequent request.",
		l.Method, l.URL, l.UsernameField, l.Username, l.PasswordField, l.Password, l.Success)
	return &s
}

// Unquote strips matching surrounding quotes from a value.
func Unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// DoLogin performs the configured HTTP login flow and returns an auth header to reuse.
func DoLogin(ctx context.Context, l *Login) (string, string, error) {
	if l == nil || l.URL == "" {
		return "", "", fmt.Errorf("no login configured")
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	form := url.Values{}
	form.Set(l.UsernameField, l.Username)
	form.Set(l.PasswordField, l.Password)

	var req *http.Request
	var err error
	if strings.ToUpper(l.Method) == "GET" {
		u, err := url.Parse(l.URL)
		if err != nil {
			return "", "", fmt.Errorf("parse login URL: %w", err)
		}
		q := u.Query()
		for k, v := range form {
			for _, vv := range v {
				q.Add(k, vv)
			}
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, l.URL, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return "", "", fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	status := resp.StatusCode
	var cookiePairs []string
	for _, c := range resp.Cookies() {
		if c != nil && c.Name != "" {
			cookiePairs = append(cookiePairs, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
	}
	body, _ := io.ReadAll(resp.Body)

	var bodyObj map[string]interface{}
	if err := json.Unmarshal(body, &bodyObj); err == nil {
		for _, k := range []string{"access_token", "token", "jwt", "id_token", "accessToken"} {
			if v, ok := bodyObj[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					return fmt.Sprintf("Authorization: Bearer %s", s), fmt.Sprintf("bearer token from JSON `%s` (HTTP %d)", k, status), nil
				}
			}
		}
	}

	if len(cookiePairs) > 0 {
		cookie := strings.Join(cookiePairs, "; ")
		ok := l.Success == "" || strings.Contains(string(body), l.Success) || status == http.StatusFound || status == http.StatusMovedPermanently || (status >= 200 && status < 300)
		extra := ""
		if !ok {
			extra = ", success marker not seen"
		}
		return fmt.Sprintf("Cookie: %s", cookie), fmt.Sprintf("session cookie captured (HTTP %d%s)", status, extra), nil
	}
	return "", "", fmt.Errorf("login returned no Set-Cookie or token (HTTP %d)", status)
}
