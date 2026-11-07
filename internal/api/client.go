// Package api is a small read-only client for the 3x-ui / still-ui panel API.
//
// It only issues GET requests, plus four POSTs that do not change the panel's
// configuration: /login and /logout (the tool's own session) and
// /panel/api/setting/all (a read that the panel routes as POST).
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/Dv2Corn/xui-doctor/internal/i18n"
)

// ErrForbidden is returned when the credentials are valid but not allowed to
// read an endpoint (for example a "monitor"-scope API token).
var ErrForbidden = i18n.Errorf("api.forbidden")

// Credentials select how the client authenticates. Token wins over a password.
type Credentials struct {
	Token         string
	Username      string
	Password      string
	TwoFactorCode string
}

// Client talks to one panel.
type Client struct {
	base     string // scheme://host:port/webBasePath without a trailing slash
	http     *http.Client
	creds    Credentials
	csrf     string
	loggedIn bool
	// PanelCert is the leaf certificate the panel presented (https only).
	PanelCert *x509.Certificate
}

// New builds a client. baseURL must include the panel's webBasePath.
func New(baseURL string, creds Credentials, insecure bool, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, i18n.Errorf("api.bad_url")
	}
	if u.User != nil {
		// Credentials in the URL would end up in output and error messages.
		return nil, i18n.Errorf("api.url_userinfo", RedactURL(u.String()))
	}
	u.RawQuery, u.Fragment = "", ""
	jar, _ := cookiejar.New(nil)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec // opt-in via --insecure
	return &Client{
		base:  strings.TrimRight(u.String(), "/"),
		http:  &http.Client{Jar: jar, Transport: tr, Timeout: timeout, CheckRedirect: noRedirect},
		creds: creds,
	}, nil
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// RedactURL drops credentials, query and the path from a URL for output:
// the panel's base path is a secret, so a non-root path becomes "/***/".
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "***"
	}
	out := ""
	if u.Host != "" {
		out = u.Scheme + "://" + u.Host
	}
	if strings.Trim(u.Path, "/") == "" {
		return out + "/"
	}
	return out + "/***/"
}

// Base returns the normalized panel URL.
func (c *Client) Base() string { return c.base }

// UsesToken reports whether the client authenticates with an API token.
func (c *Client) UsesToken() bool { return c.creds.Token != "" }

// Login opens a session when password credentials are used. With a token it is a no-op.
func (c *Client) Login(ctx context.Context) error {
	if c.UsesToken() {
		return nil
	}
	if c.creds.Username == "" || c.creds.Password == "" {
		return i18n.Errorf("api.no_credentials")
	}
	if err := c.refreshCSRF(ctx); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{
		"username":      c.creds.Username,
		"password":      c.creds.Password,
		"twoFactorCode": c.creds.TwoFactorCode,
	})
	var env envelope
	if err := c.do(ctx, http.MethodPost, "/login", body, &env); err != nil {
		return i18n.Errorf("api.login", err)
	}
	if !env.Success {
		return i18n.Errorf("api.login_refused")
	}
	c.loggedIn = true
	// still-ui clears the anonymous session (and its CSRF token) on login; 3x-ui
	// keeps it. Fetching it again works for both.
	return c.refreshCSRF(ctx)
}

// Logout ends the tool's own session. Errors are not fatal for a read-only run.
func (c *Client) Logout(ctx context.Context) error {
	if !c.loggedIn {
		return nil
	}
	c.loggedIn = false
	return c.do(ctx, http.MethodPost, "/logout", []byte("{}"), nil)
}

func (c *Client) refreshCSRF(ctx context.Context) error {
	var env envelope
	if err := c.do(ctx, http.MethodGet, "/csrf-token", nil, &env); err != nil {
		return i18n.Errorf("api.csrf", err)
	}
	var tok string
	if err := json.Unmarshal(env.Obj, &tok); err != nil || tok == "" {
		return i18n.Errorf("api.csrf_unexpected")
	}
	c.csrf = tok
	return nil
}

// Status reads GET /panel/api/server/status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var s Status
	return &s, c.getObj(ctx, http.MethodGet, "/panel/api/server/status", &s)
}

// Inbounds reads GET /panel/api/inbounds/list.
func (c *Client) Inbounds(ctx context.Context) ([]Inbound, error) {
	var in []Inbound
	err := c.getObj(ctx, http.MethodGet, "/panel/api/inbounds/list", &in)
	return in, err
}

// Hosts reads GET /panel/api/hosts/list (subscription host overrides, 3x-ui 3.x).
func (c *Client) Hosts(ctx context.Context) ([]HostGroup, error) {
	var h []HostGroup
	err := c.getObj(ctx, http.MethodGet, "/panel/api/hosts/list", &h)
	return h, err
}

// Settings reads POST /panel/api/setting/all. The route is POST but only reads;
// the panel blanks secret values in its answer.
func (c *Client) Settings(ctx context.Context) (*Settings, error) {
	var s Settings
	return &s, c.getObj(ctx, http.MethodPost, "/panel/api/setting/all", &s)
}

// Fail2ban reads GET /panel/api/server/fail2banStatus.
func (c *Client) Fail2ban(ctx context.Context) (*Fail2banStatus, error) {
	var f Fail2banStatus
	return &f, c.getObj(ctx, http.MethodGet, "/panel/api/server/fail2banStatus", &f)
}

func (c *Client) getObj(ctx context.Context, method, path string, out any) error {
	var body []byte
	if method == http.MethodPost {
		body = []byte("{}")
	}
	var env envelope
	if err := c.do(ctx, method, path, body, &env); err != nil {
		return err
	}
	if !env.Success {
		msg := env.Msg
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return i18n.Errorf("api.not_success", path, msg)
	}
	if len(env.Obj) == 0 || string(env.Obj) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Obj, out); err != nil {
		return i18n.Errorf("api.decode", path, err)
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out *envelope) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "xui-doctor")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.creds.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.creds.Token)
	} else if c.csrf != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ue, ok := err.(*url.Error); ok {
			ue.URL = path // the full URL holds the secret base path
		}
		return err
	}
	defer resp.Body.Close()
	if c.PanelCert == nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		c.PanelCert = resp.TLS.PeerCertificates[0]
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusForbidden:
		return i18n.Errorf("api.path_error", path, ErrForbidden)
	case resp.StatusCode == http.StatusUnauthorized:
		return i18n.Errorf("api.http401", path)
	case resp.StatusCode == http.StatusNotFound:
		return i18n.Errorf("api.http404", path)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return i18n.Errorf("api.redirect", path, resp.StatusCode, RedactURL(resp.Header.Get("Location")))
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return i18n.Errorf("api.not_json", path)
	}
	return nil
}
