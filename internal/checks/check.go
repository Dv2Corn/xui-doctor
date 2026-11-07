// Package checks holds the individual read-only checks. Each check gets a
// Snapshot of what was read from the panel (and optionally the local host)
// and returns findings.
package checks

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Dv2Corn/xui-doctor/internal/api"
	"github.com/Dv2Corn/xui-doctor/internal/i18n"
)

// Severity orders findings. Higher is worse.
type Severity int

const (
	OK Severity = iota
	Info
	Warn
	Critical
)

func (s Severity) String() string {
	if s >= OK && s < Critical {
		return [...]string{"OK", "INFO", "WARN"}[s]
	}
	return "CRITICAL"
}

// MarshalJSON writes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Finding is one result line. Subject, Message and Fix hold the English
// text (what JSON output carries); In renders them in another language.
type Finding struct {
	Check string `json:"check"`
	// ID names the message, stable across languages and wording changes.
	ID       string   `json:"id,omitempty"`
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject,omitempty"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`

	subject, message, fix i18n.Text
}

// newFinding builds a finding from catalog texts; fix may be the zero Text.
func newFinding(sev Severity, subject, message, fix i18n.Text) Finding {
	return Finding{ID: message.ID, Severity: sev,
		Subject: subject.String(), Message: message.String(), Fix: fix.String(),
		subject: subject, message: message, fix: fix}
}

// In returns subject, message and fix in language l. Findings built
// without catalog texts return their strings unchanged.
func (f Finding) In(l i18n.Lang) (subject, message, fix string) {
	subject, message, fix = f.Subject, f.Message, f.Fix
	if f.subject.ID != "" {
		subject = f.subject.In(l)
	}
	if f.message.ID != "" {
		message = f.message.In(l)
	}
	if f.fix.ID != "" {
		fix = f.fix.In(l)
	}
	return subject, message, fix
}

// Panel kinds.
const (
	Kind3XUI    = "3x-ui"
	KindStillUI = "still-ui"
)

// Snapshot is everything the checks may look at.
type Snapshot struct {
	Now      time.Time
	PanelURL string
	Kind     string // Kind3XUI or KindStillUI

	Status   *api.Status
	Inbounds []Inbound
	Hosts    []api.HostGroup
	Settings *api.Settings
	Fail2ban *api.Fail2banStatus

	// Errors records why a section could not be read (key: "inbounds", "hosts", ...).
	Errors map[string]error

	// PanelCert is the certificate the panel presented to this tool (https only).
	PanelCert *x509.Certificate
	// DefaultCredentials is true when the tool logged in with admin/admin.
	DefaultCredentials bool
	// AuthMethod is "token" or "password".
	AuthMethod string

	// LatestRelease is the latest release tag of the panel's repository ("" when not looked up).
	LatestRelease    string
	LatestReleaseErr string
	Offline          bool

	// Probe is set with --local / --dial-targets; nil otherwise.
	Probe Probe
	// Local is true with --local (the tool runs on the panel host).
	Local bool
	// Dial is true when REALITY targets may be dialed from where the tool runs.
	Dial bool
	// probes counts TLS handshakes made so far (see MaxTargetProbes).
	probes int
}

// Probe performs the optional host-side reads. Implemented in package local.
type Probe interface {
	// ReadCertFile parses the first certificate in a PEM file.
	ReadCertFile(path string) (*x509.Certificate, error)
	// Listening returns "tcp/443", "udp/443", ... for sockets bound on this host.
	Listening() (map[string]bool, error)
	// LookupIP resolves a host name once; the checks then dial the address
	// they vetted, so a second DNS answer cannot redirect the probe.
	LookupIP(host string) ([]net.IP, error)
	// DialTLS connects to addr (ip:port) with the given SNI, offering h2 and http/1.1.
	DialTLS(addr, sni string) (*TLSResult, error)
}

// MaxTargetProbes caps TLS handshakes per run; the target is panel data.
const MaxTargetProbes = 20

// TLSResult describes a probe handshake.
type TLSResult struct {
	Version     uint16
	ALPN        string
	VerifyError error // nil when the chain verifies for the SNI with system roots
	// UnknownRoot is true when VerifyError only says the chain does not lead
	// to a root this machine trusts (often: no CA bundle installed).
	UnknownRoot bool
}

// Check is one named check.
type Check struct {
	ID  string
	Run func(*Snapshot) []Finding
}

// All returns the checks in report order.
func All() []Check {
	return []Check{
		{ID: "xray", Run: checkXrayCompat},
		{ID: "reality", Run: checkReality},
		{ID: "tls", Run: checkTLS},
		{ID: "ports", Run: checkPorts},
		{ID: "clients", Run: checkClients},
		{ID: "security", Run: checkSecurity},
		{ID: "version", Run: checkVersion},
	}
}

// Run executes every check. A check that finds nothing yields one OK line.
func Run(s *Snapshot) []Finding {
	var out []Finding
	for _, c := range All() {
		fs := c.Run(s)
		if len(fs) == 0 {
			fs = []Finding{newFinding(OK, i18n.Text{}, i18n.T("check.ok"), i18n.Text{})}
		}
		for i := range fs {
			fs[i].Check = c.ID
		}
		out = append(out, fs...)
	}
	return out
}

// Worst returns the highest severity among findings.
func Worst(fs []Finding) Severity {
	w := OK
	for _, f := range fs {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

// Inbound is an api.Inbound with its JSON columns decoded.
type Inbound struct {
	api.Inbound
	Clients []Client
	Stream  Stream
	// ParseError is set when settings or streamSettings were not valid JSON.
	ParseError string
}

// Client is the part of settings.clients[] the checks use. Secrets (id,
// password, auth) are only compared with each other, never printed.
type Client struct {
	ID       string `json:"id"`
	Password string `json:"password"`
	Auth     string `json:"auth"`
	Email    string `json:"email"`
	Enable   bool   `json:"enable"`
	LimitIP  int    `json:"limitIp"`
}

// Stream is the part of streamSettings the checks use.
type Stream struct {
	Network         string           `json:"network"`
	Security        string           `json:"security"`
	RealitySettings *RealitySettings `json:"realitySettings"`
	TLSSettings     *TLSSettings     `json:"tlsSettings"`
}

// RealitySettings is the server side REALITY object plus the panel's
// client-facing "settings" block used to build share links.
type RealitySettings struct {
	Show         bool            `json:"show"`
	Target       json.RawMessage `json:"target"`
	Dest         json.RawMessage `json:"dest"`
	Type         string          `json:"type"`
	ServerNames  []string        `json:"serverNames"`
	PrivateKey   string          `json:"privateKey"`
	MinClientVer string          `json:"minClientVer"`
	ShortIDs     []string        `json:"shortIds"`
	Settings     struct {
		PublicKey   string `json:"publicKey"`
		Fingerprint string `json:"fingerprint"`
	} `json:"settings"`
}

// TargetString returns target (or the legacy dest) as a string; a bare
// number means a local port.
func (r *RealitySettings) TargetString() string {
	raw := r.rawTarget()
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func (r *RealitySettings) rawTarget() json.RawMessage {
	if raw := r.Target; len(raw) != 0 && string(raw) != "null" && string(raw) != `""` {
		return raw
	}
	return r.Dest
}

// TargetValid mirrors Xray-core's REALITY loader: unless "type" is set, the
// target must be a port number (a JSON number up to 65535 or a string of
// digits), a unix socket path ("/..." or "@...") or host:port.
func (r *RealitySettings) TargetValid() bool {
	if r.Type != "" {
		return true
	}
	if raw := r.rawTarget(); len(raw) > 0 && raw[0] != '"' {
		var port uint16
		return json.Unmarshal(raw, &port) == nil
	}
	s := r.TargetString()
	if s == "" {
		return false
	}
	if s[0] == '/' || s[0] == '@' {
		return true
	}
	if _, err := strconv.Atoi(s); err == nil {
		s = "localhost:" + s
	}
	_, _, err := net.SplitHostPort(s)
	return err == nil
}

// ValidClientVer mirrors Xray-core's REALITY loader for "minClientVer" and
// "maxClientVer": up to three dot-separated decimal numbers, each below 256.
func ValidClientVer(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.ParseUint(p, 10, 8); err != nil {
			return false
		}
	}
	return true
}

// TLSSettings is the part of tlsSettings the checks use.
type TLSSettings struct {
	Certificates []TLSCert `json:"certificates"`
}

// TLSCert is one certificates[] entry: a file path or inline PEM lines.
type TLSCert struct {
	CertificateFile string          `json:"certificateFile"`
	Certificate     json.RawMessage `json:"certificate"`
}

// InlinePEM returns inline certificate PEM ("" when the entry uses a file).
func (c TLSCert) InlinePEM() string {
	if len(c.Certificate) == 0 {
		return ""
	}
	var lines []string
	if json.Unmarshal(c.Certificate, &lines) == nil {
		return strings.Join(lines, "\n")
	}
	var s string
	if json.Unmarshal(c.Certificate, &s) == nil {
		return s
	}
	return ""
}

// DecodeInbounds turns API inbounds into Inbounds. Bad JSON is recorded, not fatal.
func DecodeInbounds(in []api.Inbound) []Inbound {
	out := make([]Inbound, 0, len(in))
	for _, a := range in {
		ib := Inbound{Inbound: a}
		if strings.TrimSpace(string(a.Settings)) != "" {
			var s struct {
				Clients []Client `json:"clients"`
			}
			if err := json.Unmarshal(a.Settings, &s); err != nil {
				ib.ParseError = "settings: " + err.Error()
			}
			ib.Clients = s.Clients
		}
		if strings.TrimSpace(string(a.StreamSettings)) != "" {
			if err := json.Unmarshal(a.StreamSettings, &ib.Stream); err != nil {
				ib.ParseError = "streamSettings: " + err.Error()
			}
		}
		out = append(out, ib)
	}
	return out
}

// label names an inbound in findings without exposing secrets.
func (ib *Inbound) label() i18n.Text {
	r := ib.Remark
	if r == "" {
		r = ib.Tag
	}
	return i18n.T("inbound.label", ib.ID, r, ib.Protocol, ib.Port)
}

// local reports whether the inbound runs on this panel's own Xray (not on a node).
func (ib *Inbound) local() bool { return ib.NodeID == nil }

func (s *Snapshot) skipped(section string) (Finding, bool) {
	err, ok := s.Errors[section]
	if !ok || err == nil {
		return Finding{}, false
	}
	var name any = section
	switch section {
	case "inbounds":
		name = i18n.T("section.inbounds")
	case "hosts":
		name = i18n.T("section.hosts")
	case "settings":
		name = i18n.T("section.settings")
	case "fail2ban":
		name = i18n.T("section.fail2ban")
	}
	var why any = err // a catalog error renders in the report's language
	var ce *i18n.Error
	switch {
	case errors.Is(err, api.ErrForbidden):
		why = i18n.T("section.not_permitted")
	case !errors.As(err, &ce):
		if msg := err.Error(); len(msg) > 200 {
			why = msg[:200]
		}
	}
	return newFinding(Info, i18n.Text{}, i18n.T("check.skipped", name, why), i18n.Text{}), true
}
