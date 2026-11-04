package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Dv2Corn/xui-doctor/internal/api"
)

var now = time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)

const fakePriv = "ERERERERERERERERERERERERERERERERERERERERERE" // 32 bytes base64url
const fakePub = "QEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEA"

func realityInbound(id, port int, fp string, mut func(map[string]any)) Inbound {
	rs := map[string]any{
		"show": false, "target": "example.com:443", "serverNames": []string{"example.com"},
		"privateKey": fakePriv, "minClientVer": "", "shortIds": []string{"0123abcd", ""},
		"settings": map[string]any{"publicKey": fakePub, "fingerprint": fp, "spiderX": "/"},
	}
	if mut != nil {
		mut(rs)
	}
	stream, _ := json.Marshal(map[string]any{"network": "tcp", "security": "reality", "realitySettings": rs})
	settings, _ := json.Marshal(map[string]any{"clients": []map[string]any{{"id": "00000000-0000-4000-8000-000000000001", "email": "a", "enable": true}}})
	return DecodeInbounds([]api.Inbound{{ID: id, Remark: "r" + fp, Enable: true, Port: port, Protocol: "vless", Settings: settings, StreamSettings: stream}})[0]
}

func snap(xray string, ibs ...Inbound) *Snapshot {
	st := &api.Status{PanelVersion: "3.11.0"}
	st.Xray.State, st.Xray.Version = "running", xray
	return &Snapshot{Now: now, Kind: Kind3XUI, Status: st, Inbounds: ibs, Errors: map[string]string{}, Offline: true}
}

func count(fs []Finding, sev Severity, substr string) int {
	n := 0
	for _, f := range fs {
		if f.Severity == sev && strings.Contains(f.Subject+" "+f.Message, substr) {
			n++
		}
	}
	return n
}

func TestXrayBoundaries(t *testing.T) {
	ios := realityInbound(1, 443, "ios", nil)
	cases := []struct {
		xray               string
		crit, warn, okLine int
	}{
		{"26.6.27", 0, 0, 1},
		{"26.7.11", 0, 1, 0}, // default minClientVer
		{"26.7.28", 0, 1, 0},
		{"26.9.8", 1, 1, 0}, // fp=ios + sing-box/mihomo line
		{"26.9.9", 1, 1, 0},
		{"26.10.31", 1, 1, 0},
	}
	for _, c := range cases {
		fs := checkXrayCompat(snap(c.xray, ios))
		if got := count(fs, Critical, ""); got != c.crit {
			t.Errorf("%s: critical=%d want %d: %+v", c.xray, got, c.crit, fs)
		}
		if got := count(fs, Warn, ""); got != c.warn {
			t.Errorf("%s: warn=%d want %d: %+v", c.xray, got, c.warn, fs)
		}
		if got := count(fs, OK, ""); got != c.okLine {
			t.Errorf("%s: ok=%d want %d", c.xray, got, c.okLine)
		}
	}
}

func TestXrayFingerprintClasses(t *testing.T) {
	for fp, want := range map[string]Severity{
		"chrome": OK, "firefox": OK, "safari": OK, "": OK,
		"ios": Critical, "edge": Critical, "qq": Critical, "360": Critical, "android": Critical,
		"random": Warn, "randomized": Warn, "randomizednoalpn": Warn, "unsafe": Info,
	} {
		fs := checkXrayCompat(snap("26.10.31", realityInbound(1, 443, fp, nil)))
		got := OK
		for _, f := range fs {
			if f.Subject == "REALITY clients" {
				continue // the general sing-box/mihomo line
			}
			if f.Severity > got {
				got = f.Severity
			}
		}
		if got != want {
			t.Errorf("fp=%q: %s want %s", fp, got, want)
		}
	}
}

func TestXrayMinClientVerSet(t *testing.T) {
	ib := realityInbound(1, 443, "ios", func(m map[string]any) { m["minClientVer"] = "0.0.0" })
	fs := checkXrayCompat(snap("26.7.28", ib))
	if count(fs, Warn, "") != 0 || count(fs, OK, "minClientVer explicitly") != 1 {
		t.Fatalf("%+v", fs)
	}
}

func TestXrayHostsAndNodes(t *testing.T) {
	ib := realityInbound(1, 443, "chrome", nil)
	node := realityInbound(2, 443, "ios", nil)
	n := 7
	node.NodeID = &n
	s := snap("26.10.31", ib, node)
	s.Hosts = []api.HostGroup{
		{Remark: "cdn", InboundIDs: []int{1}, Security: "same", Fingerprint: "qq"},
		{Remark: "off", InboundIDs: []int{1}, Security: "same", Fingerprint: "ios", IsDisabled: true},
		{Remark: "tls-host", InboundIDs: []int{1}, Security: "tls", Fingerprint: "ios"},
		{Remark: "mh", InboundIDs: []int{1}, MihomoX25519: true},
	}
	fs := checkXrayCompat(s)
	if count(fs, Critical, `host "cdn"`) != 1 || count(fs, Critical, "Mihomo X25519") != 1 {
		t.Fatalf("host findings: %+v", fs)
	}
	if count(fs, Critical, `"off"`)+count(fs, Critical, "tls-host") != 0 {
		t.Fatal("disabled or non-REALITY hosts must be ignored")
	}
	if count(fs, Info, "remote nodes") != 1 || count(fs, Critical, "rios") != 0 {
		t.Fatalf("node inbound handling: %+v", fs)
	}
}

func TestXrayNotRunningAndUnreadable(t *testing.T) {
	s := snap("26.10.31")
	s.Status.Xray.State, s.Status.Xray.ErrorMsg = "error", "failed to listen\nmore"
	s.Inbounds = nil
	s.Errors["inbounds"] = "forbidden"
	fs := checkXrayCompat(s)
	if count(fs, Critical, "not running (state: error): failed to listen") != 1 {
		t.Fatalf("%+v", fs)
	}
	if count(fs, Warn, "could not be read") != 1 {
		t.Fatalf("monitor-token warning missing: %+v", fs)
	}
}

func TestRealityValidation(t *testing.T) {
	bad := realityInbound(1, 443, "chrome", func(m map[string]any) {
		m["target"] = ""
		m["serverNames"] = []string{}
		m["privateKey"] = "short"
		m["shortIds"] = []string{"abc", "0123456789abcdef01"}
		m["show"] = true
		m["settings"].(map[string]any)["publicKey"] = ""
	})
	fs := checkReality(snap("26.10.31", bad))
	for _, want := range []string{`empty "target"`, `empty "serverNames"`, `"privateKey" is not`, "shortIds[0]", "shortIds[1]"} {
		if count(fs, Critical, want) != 1 {
			t.Errorf("missing critical %q in %+v", want, fs)
		}
	}
	if count(fs, Warn, "no pbk") != 1 || count(fs, Info, `"show"`) != 1 {
		t.Errorf("pbk/show: %+v", fs)
	}
	dest := realityInbound(2, 443, "chrome", func(m map[string]any) { delete(m, "target"); m["dest"] = 8443 })
	if got := dest.Stream.RealitySettings.TargetString(); got != "8443" {
		t.Fatalf("dest alias: %q", got)
	}
	if fs := checkReality(snap("26.10.31", realityInbound(3, 443, "chrome", nil))); len(fs) != 0 {
		t.Fatalf("clean inbound produced %+v", fs)
	}
}

type fakeProbe struct {
	certs  map[string]*x509.Certificate
	listen map[string]bool
	dns    map[string][]net.IP
	dial   func(addr, sni string) (*TLSResult, error)
}

func (p fakeProbe) LookupIP(host string) ([]net.IP, error) {
	if ips, ok := p.dns[host]; ok {
		return ips, nil
	}
	return nil, errors.New("no such host")
}

func (p fakeProbe) ReadCertFile(path string) (*x509.Certificate, error) {
	if c, ok := p.certs[path]; ok {
		return c, nil
	}
	return nil, errors.New("open " + path + ": no such file or directory")
}
func (p fakeProbe) Listening() (map[string]bool, error) { return p.listen, nil }
func (p fakeProbe) DialTLS(addr, sni string) (*TLSResult, error) {
	return p.dial(addr, sni)
}

func TestRealityDial(t *testing.T) {
	s := snap("26.10.31", realityInbound(1, 443, "chrome", func(m map[string]any) {
		m["serverNames"] = []string{"good.example", "tls12.example", "nocert.example", "down.example", "noroots.example"}
	}))
	s.Dial = true
	s.Probe = fakeProbe{dns: map[string][]net.IP{"example.com": {net.ParseIP("93.184.216.34")}}, dial: func(addr, sni string) (*TLSResult, error) {
		if addr != "93.184.216.34:443" {
			t.Errorf("addr %s", addr)
		}
		switch sni {
		case "tls12.example":
			return &TLSResult{Version: tls.VersionTLS12, ALPN: "http/1.1"}, nil
		case "nocert.example":
			return &TLSResult{Version: tls.VersionTLS13, ALPN: "h2", VerifyError: errors.New("x509: certificate is valid for other.example")}, nil
		case "down.example":
			return nil, errors.New("connection refused")
		case "noroots.example":
			return &TLSResult{Version: tls.VersionTLS13, ALPN: "h2", VerifyError: errors.New("x509: certificate signed by unknown authority"), UnknownRoot: true}, nil
		}
		return &TLSResult{Version: tls.VersionTLS13, ALPN: "h2"}, nil
	}}
	fs := checkReality(s)
	if count(fs, Critical, "TLS 1.3") != 1 || count(fs, Warn, "did not select h2") != 1 ||
		count(fs, Warn, "does not verify") != 1 || count(fs, Critical, "connection refused") != 1 ||
		count(fs, Info, "CA store") != 1 {
		t.Fatalf("%+v", fs)
	}
	if count(fs, Critical, "not necessarily the panel host") == 0 {
		t.Error("remote dial must say where it dialed from")
	}
}

func selfSigned(t *testing.T, notAfter time.Time) (*x509.Certificate, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t.example"},
		NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func tlsInbound(id, port int, cert map[string]any) Inbound {
	stream, _ := json.Marshal(map[string]any{"network": "tcp", "security": "tls",
		"tlsSettings": map[string]any{"certificates": []any{cert}}})
	return DecodeInbounds([]api.Inbound{{ID: id, Remark: "tls", Enable: true, Port: port, Protocol: "trojan", Settings: api.JSONDoc(`{"clients":[]}`), StreamSettings: stream}})[0]
}

func TestTLS(t *testing.T) {
	_, expiredPEM := selfSigned(t, now.Add(-time.Hour))
	soon, _ := selfSigned(t, now.Add(50*time.Hour))
	fine, _ := selfSigned(t, now.Add(60*24*time.Hour))
	s := snap("26.10.31",
		tlsInbound(1, 443, map[string]any{"certificate": strings.Split(strings.TrimSpace(expiredPEM), "\n")}),
		tlsInbound(2, 444, map[string]any{"certificateFile": "/c/soon.pem"}),
		tlsInbound(3, 445, map[string]any{"certificateFile": "/c/missing.pem"}),
	)
	s.PanelCert = fine
	fs := checkTLS(s)
	if count(fs, Critical, "expired") != 1 || count(fs, Info, "2 certificate files not checked") != 1 || count(fs, OK, "panel HTTPS") != 1 {
		t.Fatalf("without --local: %+v", fs)
	}
	s.Local = true
	s.Probe = fakeProbe{certs: map[string]*x509.Certificate{"/c/soon.pem": soon}}
	fs = checkTLS(s)
	if count(fs, Warn, "expires in 2 days 2 hours") != 1 || count(fs, Critical, "no such file") != 1 {
		t.Fatalf("with --local: %+v", fs)
	}
}

func TestPorts(t *testing.T) {
	a := realityInbound(1, 443, "chrome", nil)
	b := realityInbound(2, 443, "chrome", nil) // same tcp/443, wildcard listen
	c := realityInbound(3, 8443, "chrome", nil)
	c.Listen = "127.0.0.1"
	d := realityInbound(4, 8443, "chrome", nil)
	d.Listen = "127.0.0.2" // different address: fine
	hy := DecodeInbounds([]api.Inbound{{ID: 5, Remark: "hy", Enable: true, Port: 443, Protocol: "hysteria", StreamSettings: api.JSONDoc(`{"network":"hysteria","security":"tls"}`)}})[0]
	off := realityInbound(6, 443, "chrome", nil)
	off.Enable = false
	n := 2
	node := realityInbound(7, 443, "chrome", nil)
	node.NodeID = &n
	s := snap("26.10.31", a, b, c, d, hy, off, node)
	s.Settings = &api.Settings{WebPort: 8443, WebListen: "", SubEnable: true, SubPort: 2096}
	fs := checkPorts(s)
	if count(fs, Critical, "tcp/443") != 1 {
		t.Errorf("tcp/443 conflict: %+v", fs)
	}
	// panel on all addresses collides with both 8443 inbounds
	if count(fs, Critical, "tcp/8443") != 2 {
		t.Errorf("panel port conflict: %+v", fs)
	}
	if count(fs, Critical, "udp/") != 0 || count(fs, Critical, "node") != 0 {
		t.Errorf("udp or node inbounds must not collide: %+v", fs)
	}
	s.Settings = nil
	s.Local = true
	s.Probe = fakeProbe{listen: map[string]bool{"tcp/443": true, "udp/443": true, "tcp/8443": true}}
	s.Inbounds = []Inbound{a, hy, realityInbound(9, 9999, "chrome", nil)}
	fs = checkPorts(s)
	if count(fs, Warn, "nothing listens on tcp/9999") != 1 || count(fs, Warn, "nothing listens") != 1 {
		t.Errorf("listening: %+v", fs)
	}
}

func TestTransports(t *testing.T) {
	mk := func(proto, settings, stream string) []string {
		ib := DecodeInbounds([]api.Inbound{{Protocol: proto, Settings: api.JSONDoc(settings), StreamSettings: api.JSONDoc(stream)}})[0]
		return transports(&ib)
	}
	for _, c := range []struct {
		proto, settings, stream, want string
	}{
		{"vless", `{}`, `{"network":"tcp"}`, "tcp"},
		{"vless", `{}`, `{"network":"kcp"}`, "udp"},
		{"shadowsocks", `{"network":"tcp,udp"}`, `{}`, "tcp,udp"},
		{"tunnel", `{"allowedNetwork":"udp"}`, `{}`, "udp"},
		{"mixed", `{"udp":true}`, `{}`, "tcp,udp"},
		{"wireguard", `{}`, `{}`, "udp"},
		{"masque", `{}`, `{"tlsSettings":{"alpn":["h2","h3"]}}`, "tcp,udp"},
		{"masque", `{}`, `{"tlsSettings":{"alpn":["h3"]}}`, "udp"},
	} {
		if got := strings.Join(mk(c.proto, c.settings, c.stream), ","); got != c.want {
			t.Errorf("%s %s: %s want %s", c.proto, c.settings, got, c.want)
		}
	}
}

func TestClients(t *testing.T) {
	settings := api.JSONDoc(`{"clients":[
	 {"id":"00000000-0000-4000-8000-0000000000aa","email":"a","enable":true,"limitIp":2},
	 {"id":"00000000-0000-4000-8000-0000000000AA","email":"b","enable":true},
	 {"id":"00000000-0000-4000-8000-0000000000cc","email":"c","enable":true}]}`)
	ib := DecodeInbounds([]api.Inbound{{ID: 1, Remark: "x", Enable: true, Port: 443, Protocol: "vless", Settings: settings,
		StreamSettings: api.JSONDoc(`{"network":"tcp","security":"none"}`),
		ClientStats: []api.ClientTraffic{
			{Email: "a", Enable: true, ExpiryTime: now.Add(-time.Hour).UnixMilli()},
			{Email: "b", Enable: true, Total: 100, Up: 60, Down: 50},
			{Email: "c", Enable: false, ExpiryTime: now.Add(-time.Hour).UnixMilli()}, // already disabled
			{Email: "d", Enable: true, ExpiryTime: -86400000},                        // starts on first use
		}}})[0]
	// The same client attached to a second inbound is normal in 3x-ui 3.x.
	ib2 := ib
	ib2.ID = 2
	s := snap("26.10.31", ib, ib2)
	s.Fail2ban = &api.Fail2banStatus{Enabled: true, Installed: false}
	fs := checkClients(s)
	if count(fs, Warn, `"a" and "b" share one credential`) != 2 {
		t.Errorf("duplicate UUID per inbound: %+v", fs)
	}
	if count(fs, Warn, "1 client is past expiry") != 1 || count(fs, Warn, "1 client has used up") != 1 {
		t.Errorf("expired/exhausted: %+v", fs)
	}
	if count(fs, Warn, "not enforced") != 1 {
		t.Errorf("fail2ban: %+v", fs)
	}
	s.Fail2ban = &api.Fail2banStatus{Enabled: true, Installed: true, Usable: true}
	if count(checkClients(s), Info, "IP limit") != 1 {
		t.Error("usable fail2ban should be INFO")
	}
}

func TestSecurity(t *testing.T) {
	s := snap("26.10.31")
	s.PanelURL = "http://198.51.100.7:2053/"
	s.DefaultCredentials = true
	s.Settings = &api.Settings{WebPort: 2053, WebBasePath: "/", SubEnable: true, SubPath: "/sub/",
		SubJSONEnable: true, SubJSONURI: "https://sub.example/json/", HasTgBotToken: true, TgBotEnable: true}
	fs := checkSecurity(s)
	for _, want := range []struct {
		sev Severity
		sub string
	}{
		{Critical, "admin/admin"}, {Critical, "plain HTTP on a non-loopback"}, {Warn, `base path is "/"`},
		{Info, "default port 2053"}, {Info, `"/sub/"`}, {Info, `"/json/"`}, {Warn, "plain HTTP on all addresses"},
		{Warn, "two-factor"}, {Info, "Telegram bot token is enabled"},
	} {
		if count(fs, want.sev, want.sub) != 1 {
			t.Errorf("missing %s %q in %+v", want.sev, want.sub, fs)
		}
	}
	s = snap("26.10.31")
	s.PanelURL = "https://panel.example:8443/x7Kq/"
	s.Settings = &api.Settings{WebPort: 8443, WebBasePath: "/x7Kq/", WebCertFile: "/c.pem", WebKeyFile: "/k.pem",
		TwoFactorEnable: true, SubEnable: true, SubPath: "/abc/"}
	if fs := checkSecurity(s); len(fs) != 0 {
		t.Fatalf("hardened panel produced %+v", fs)
	}
}

func TestVersion(t *testing.T) {
	s := snap("26.10.31")
	s.Offline = false
	s.LatestRelease = "v3.11.1"
	if fs := checkVersion(s); count(fs, Warn, "older than the latest release 3.11.1 of MHSanaei/3x-ui") != 1 {
		t.Fatalf("%+v", fs)
	}
	s.LatestRelease = "v3.11.0"
	if fs := checkVersion(s); count(fs, OK, "latest") != 1 {
		t.Fatalf("%+v", fs)
	}
	s.LatestRelease, s.LatestReleaseErr = "", "GitHub API: HTTP 403"
	if fs := checkVersion(s); count(fs, Info, "lookup failed") != 1 {
		t.Fatalf("%+v", fs)
	}
}

func TestRunAddsOKAndWorst(t *testing.T) {
	fs := Run(snap("26.6.27"))
	if Worst(fs) > Info {
		t.Fatalf("empty clean panel: %+v", fs)
	}
	for _, f := range fs {
		if f.Check == "" {
			t.Fatal("check id missing")
		}
	}
}

func TestJSONDocBothForms(t *testing.T) {
	var a, b api.Inbound
	if err := json.Unmarshal([]byte(`{"settings":"{\"clients\":[]}","streamSettings":{"security":"reality"}}`), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"settings":{"clients":[]},"streamSettings":"{\"security\":\"reality\"}"}`), &b); err != nil {
		t.Fatal(err)
	}
	da, db := DecodeInbounds([]api.Inbound{a})[0], DecodeInbounds([]api.Inbound{b})[0]
	if da.Stream.Security != "reality" || db.Stream.Security != "reality" || da.ParseError != "" || db.ParseError != "" {
		t.Fatalf("%+v %+v", da, db)
	}
}

func TestRealityDialPolicy(t *testing.T) {
	var dialed []string
	probe := fakeProbe{
		dns: map[string][]net.IP{
			"public.example":  {net.ParseIP("93.184.216.34")},
			"private.example": {net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.5")},
			"meta.example":    {net.ParseIP("169.254.169.254")},
			"cgnat.example":   {net.ParseIP("100.64.1.1")},
		},
		dial: func(addr, sni string) (*TLSResult, error) {
			dialed = append(dialed, addr)
			return &TLSResult{Version: tls.VersionTLS13, ALPN: "h2"}, nil
		},
	}
	run := func(local bool, target string) []Finding {
		dialed = nil
		s := snap("26.10.31", realityInbound(1, 443, "chrome", func(m map[string]any) { m["target"] = target }))
		s.Dial, s.Local, s.Probe = true, local, probe
		return checkReality(s)
	}
	for _, target := range []string{"private.example:443", "meta.example:443", "cgnat.example:443", "8443", "127.0.0.1:443", "[::1]:443", "0.0.0.0:443"} {
		fs := run(false, target)
		if len(dialed) != 0 || count(fs, Info, "not dialed") != 1 {
			t.Errorf("%s dialed without --local: %v %+v", target, dialed, fs)
		}
	}
	if run(true, "8443"); len(dialed) != 1 || dialed[0] != "127.0.0.1:8443" {
		t.Errorf("--local must dial local targets: %v", dialed)
	}
	if run(false, "public.example:8443"); len(dialed) != 1 || dialed[0] != "93.184.216.34:8443" {
		t.Errorf("must dial the address resolved once: %v", dialed)
	}
	if fs := run(false, "nxdomain.example:443"); count(fs, Info, "cannot resolve") != 1 || len(dialed) != 0 {
		t.Errorf("unresolvable: %+v", fs)
	}
}

func TestRealityDialCap(t *testing.T) {
	names := make([]string, 25)
	for i := range names {
		names[i] = "n" + string(rune('a'+i)) + ".example"
	}
	dials := 0
	s := snap("26.10.31", realityInbound(1, 443, "chrome", func(m map[string]any) { m["target"] = "93.184.216.34:443"; m["serverNames"] = names }))
	s.Dial = true
	s.Probe = fakeProbe{dial: func(addr, sni string) (*TLSResult, error) {
		dials++
		return &TLSResult{Version: tls.VersionTLS13, ALPN: "h2"}, nil
	}}
	fs := checkReality(s)
	if dials != MaxTargetProbes || count(fs, Info, "5 server names not dialed") != 1 {
		t.Fatalf("dials=%d %+v", dials, fs)
	}
}
