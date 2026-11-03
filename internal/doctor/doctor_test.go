package doctor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dv2Corn/xui-doctor/internal/api"
	"github.com/Dv2Corn/xui-doctor/internal/checks"
)

// fakePanel serves recorded fixtures behind the same auth rules as a 3x-ui /
// still-ui panel: CSRF token for session POSTs, session cookie or Bearer token
// for /panel/api, 404 for unauthenticated API calls.
type fakePanel struct {
	t        *testing.T
	dir      string
	base     string
	user     string
	pass     string
	token    string
	rotate   bool // still-ui: login clears the anonymous session and its CSRF token
	mu       sync.Mutex
	sessions map[string]string // cookie -> csrf
	loggedIn map[string]bool
	calls    []string
	logouts  int
}

func newFakePanel(t *testing.T, fixture string, rotate bool) (*fakePanel, *httptest.Server) {
	fp := &fakePanel{t: t, dir: filepath.Join("..", "..", "testdata", fixture), base: "/xd-base",
		user: "tester", pass: "fake-pass", token: "fake-token", rotate: rotate,
		sessions: map[string]string{}, loggedIn: map[string]bool{}}
	srv := httptest.NewServer(fp)
	t.Cleanup(srv.Close)
	return fp, srv
}

func (p *fakePanel) fixture(name string) []byte {
	b, err := os.ReadFile(filepath.Join(p.dir, name+".json"))
	if err != nil {
		p.t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

func (p *fakePanel) session(w http.ResponseWriter, r *http.Request, fresh bool) string {
	if c, err := r.Cookie("3x-ui"); err == nil && !fresh {
		if _, ok := p.sessions[c.Value]; ok {
			return c.Value
		}
	}
	id := "s" + time.Now().Format("150405.000000000")
	p.sessions[id] = "csrf-" + id
	http.SetCookie(w, &http.Cookie{Name: "3x-ui", Value: id, Path: p.base})
	return id
}

func (p *fakePanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, r.Method+" "+strings.TrimPrefix(r.URL.Path, p.base))
	if !strings.HasPrefix(r.URL.Path, p.base+"/") {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, p.base)
	bearer := r.Header.Get("Authorization") == "Bearer "+p.token
	var sid string
	if !bearer {
		sid = p.session(w, r, false)
		if r.Method == http.MethodPost && r.Header.Get("X-CSRF-Token") != p.sessions[sid] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}
	ok := func(obj any) {
		raw, _ := json.Marshal(obj)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "msg": "", "obj": json.RawMessage(raw)})
	}
	switch {
	case path == "/csrf-token" && r.Method == http.MethodGet:
		ok(p.sessions[sid])
		return
	case path == "/login" && r.Method == http.MethodPost:
		var f struct{ Username, Password string }
		_ = json.NewDecoder(r.Body).Decode(&f)
		if f.Username != p.user || f.Password != p.pass {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "msg": "Wrong username or password"})
			return
		}
		if p.rotate {
			delete(p.sessions, sid)
			sid = p.session(w, r, true)
		}
		p.loggedIn[sid] = true
		ok(nil)
		return
	case path == "/logout" && r.Method == http.MethodPost:
		p.logouts++
		delete(p.loggedIn, sid)
		_, _ = w.Write([]byte(`{"success":true}`))
		return
	}
	if !strings.HasPrefix(path, "/panel/api/") {
		http.NotFound(w, r)
		return
	}
	if !bearer && !p.loggedIn[sid] {
		http.NotFound(w, r) // the panel hides its API from anonymous callers
		return
	}
	routes := map[string]string{
		"GET /panel/api/server/status":         "status",
		"GET /panel/api/inbounds/list":         "inbounds",
		"GET /panel/api/hosts/list":            "hosts",
		"POST /panel/api/setting/all":          "settings",
		"GET /panel/api/server/fail2banStatus": "fail2ban",
	}
	name, found := routes[r.Method+" "+path]
	if !found {
		p.t.Errorf("unexpected call %s %s", r.Method, path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = w.Write(p.fixture(name))
}

func collect(t *testing.T, srv *httptest.Server, creds api.Credentials) *checks.Snapshot {
	t.Helper()
	s, err := Collect(context.Background(), Options{URL: srv.URL + "/xd-base/", Creds: creds, Timeout: 5 * time.Second, Offline: true})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return s
}

func findings(s *checks.Snapshot) []checks.Finding { return checks.Run(s) }

func has(fs []checks.Finding, sev checks.Severity, check, substr string) bool {
	for _, f := range fs {
		if f.Severity == sev && f.Check == check && strings.Contains(f.Subject+" "+f.Message, substr) {
			return true
		}
	}
	return false
}

func TestCollect3XUIPassword(t *testing.T) {
	fp, srv := newFakePanel(t, "3x-ui-3.11.0", false)
	s := collect(t, srv, api.Credentials{Username: "tester", Password: "fake-pass"})
	if s.Kind != checks.Kind3XUI || s.Status.PanelVersion != "3.11.0" || s.Status.Xray.Version != "26.10.21" {
		t.Fatalf("kind/version: %s %s %s", s.Kind, s.Status.PanelVersion, s.Status.Xray.Version)
	}
	if len(s.Errors) != 0 {
		t.Fatalf("errors: %v", s.Errors)
	}
	if len(s.Inbounds) != 4 || len(s.Hosts) != 1 || s.Settings == nil || s.Fail2ban == nil {
		t.Fatalf("snapshot incomplete: %d inbounds, %d hosts", len(s.Inbounds), len(s.Hosts))
	}
	fs := findings(s)
	for _, want := range []struct {
		sev          checks.Severity
		check, match string
	}{
		{checks.Critical, "xray", "fp=ios"},
		{checks.Critical, "xray", "fp=edge"},
		{checks.Critical, "xray", "Mihomo X25519"},
		{checks.Warn, "xray", "sing-box"},
		{checks.Critical, "tls", "trojan-tls-inline"},
		{checks.Warn, "clients", "fail2ban is not usable"},
		{checks.Warn, "security", "two-factor"},
	} {
		if !has(fs, want.sev, want.check, want.match) {
			t.Errorf("missing %s [%s] %q", want.sev, want.check, want.match)
		}
	}
	if has(fs, checks.Critical, "xray", "reality-chrome") {
		t.Error("the chrome inbound must not be flagged")
	}
	if fp.logouts != 1 {
		t.Errorf("logouts = %d, want 1", fp.logouts)
	}
	assertReadOnly(t, fp.calls)
}

func TestCollectStillUIPasswordRotatesCSRF(t *testing.T) {
	fp, srv := newFakePanel(t, "still-ui-1.3.0", true)
	s := collect(t, srv, api.Credentials{Username: "tester", Password: "fake-pass"})
	if s.Kind != checks.KindStillUI || s.Status.UpstreamVersion != "3.11.0" || s.Status.PanelVersion != "1.3.0" {
		t.Fatalf("still-ui not detected: %s %q", s.Kind, s.Status.UpstreamVersion)
	}
	if _, bad := s.Errors["settings"]; bad {
		t.Fatalf("settings not read after CSRF rotation: %v", s.Errors)
	}
	fs := findings(s)
	if !has(fs, checks.Critical, "xray", "Xray 26.10.31") {
		t.Error("missing ML-KEM finding for still-ui")
	}
	if !has(fs, checks.Info, "version", "") && !has(fs, checks.OK, "version", "") {
		t.Error("missing version line")
	}
	if fp.logouts != 1 {
		t.Errorf("logouts = %d", fp.logouts)
	}
	assertReadOnly(t, fp.calls)
}

func TestCollectToken(t *testing.T) {
	fp, srv := newFakePanel(t, "3x-ui-3.11.0", false)
	s := collect(t, srv, api.Credentials{Token: "fake-token"})
	if s.AuthMethod != "API token" || len(s.Errors) != 0 {
		t.Fatalf("token auth: %s %v", s.AuthMethod, s.Errors)
	}
	for _, c := range fp.calls {
		if strings.Contains(c, "/login") || strings.Contains(c, "/logout") || strings.Contains(c, "/csrf-token") {
			t.Errorf("token run should not touch sessions: %s", c)
		}
	}
	assertReadOnly(t, fp.calls)
}

func TestCollectFatal(t *testing.T) {
	_, srv := newFakePanel(t, "3x-ui-3.11.0", false)
	_, err := Collect(context.Background(), Options{URL: srv.URL + "/xd-base/", Creds: api.Credentials{Username: "tester", Password: "wrong"}, Timeout: 5 * time.Second, Offline: true})
	if err == nil || !strings.Contains(err.Error(), "login refused") {
		t.Fatalf("want login refused, got %v", err)
	}
	_, err = Collect(context.Background(), Options{URL: srv.URL + "/wrong/", Creds: api.Credentials{Token: "fake-token"}, Timeout: 5 * time.Second, Offline: true})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want 404 for wrong base path, got %v", err)
	}
	_, err = Collect(context.Background(), Options{URL: srv.URL + "/xd-base/", Timeout: 5 * time.Second, Offline: true})
	if err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("want no credentials, got %v", err)
	}
}

func TestLatestRelease(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/Dv2Corn/still-ui/releases/latest" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"tag_name":"v1.4.0"}`))
	}))
	defer gh.Close()
	old := api.GitHubAPI
	api.GitHubAPI = gh.URL
	defer func() { api.GitHubAPI = old }()
	_, srv := newFakePanel(t, "still-ui-1.3.0", true)
	s, err := Collect(context.Background(), Options{URL: srv.URL + "/xd-base", Creds: api.Credentials{Token: "fake-token"}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if s.LatestRelease != "v1.4.0" {
		t.Fatalf("latest = %q (%s)", s.LatestRelease, s.LatestReleaseErr)
	}
	if !has(findings(s), checks.Warn, "version", "older than the latest release 1.4.0 of Dv2Corn/still-ui") {
		t.Error("missing outdated warning")
	}
}

// assertReadOnly fails on any request outside the read-only set.
func assertReadOnly(t *testing.T, calls []string) {
	t.Helper()
	allowed := map[string]bool{
		"GET /csrf-token": true, "POST /login": true, "POST /logout": true,
		"GET /panel/api/server/status": true, "GET /panel/api/inbounds/list": true,
		"GET /panel/api/hosts/list": true, "POST /panel/api/setting/all": true,
		"GET /panel/api/server/fail2banStatus": true,
	}
	for _, c := range calls {
		if !allowed[c] {
			t.Errorf("request outside the read-only set: %s", c)
		}
	}
}
