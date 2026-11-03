// Package checks holds the individual read-only checks. Each check gets a
// Snapshot of what was read from the panel (and optionally the local host)
// and returns findings.
package checks

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Dv2Corn/xui-doctor/internal/api"
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
	switch s {
	case OK:
		return "OK"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	default:
		return "CRITICAL"
	}
}

// MarshalJSON writes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Finding is one result line.
type Finding struct {
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject,omitempty"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
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
	Errors map[string]string

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
}

// Probe performs the optional host-side reads. Implemented in package local.
type Probe interface {
	// ReadCertFile parses the first certificate in a PEM file.
	ReadCertFile(path string) (*x509.Certificate, error)
	// Listening returns "tcp/443", "udp/443", ... for sockets bound on this host.
	Listening() (map[string]bool, error)
	// DialTLS connects to addr with the given SNI, offering h2 and http/1.1.
	DialTLS(addr, sni string) (*TLSResult, error)
}

// TLSResult describes a probe handshake.
type TLSResult struct {
	Version     uint16
	ALPN        string
	Leaf        *x509.Certificate
	VerifyError error // nil when the chain verifies for the SNI with system roots
	// UnknownRoot is true when VerifyError only says the chain does not lead
	// to a root this machine trusts (often: no CA bundle installed).
	UnknownRoot bool
}

// Check is one named check.
type Check struct {
	ID   string
	Name string
	Run  func(*Snapshot) []Finding
}

// All returns the checks in report order.
func All() []Check {
	return []Check{
		{ID: "xray", Name: "Xray core and REALITY client compatibility", Run: checkXrayCompat},
		{ID: "reality", Name: "REALITY inbound settings", Run: checkReality},
		{ID: "tls", Name: "TLS certificates", Run: checkTLS},
		{ID: "ports", Name: "Port conflicts", Run: checkPorts},
		{ID: "clients", Name: "Clients", Run: checkClients},
		{ID: "security", Name: "Panel security", Run: checkSecurity},
		{ID: "version", Name: "Panel version", Run: checkVersion},
	}
}

// Run executes every check. A check that finds nothing yields one OK line.
func Run(s *Snapshot) []Finding {
	var out []Finding
	for _, c := range All() {
		fs := c.Run(s)
		if len(fs) == 0 {
			fs = []Finding{{Severity: OK, Message: "no problems found"}}
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
	ID         string `json:"id"`
	Password   string `json:"password"`
	Auth       string `json:"auth"`
	Email      string `json:"email"`
	Enable     bool   `json:"enable"`
	LimitIP    int    `json:"limitIp"`
	TotalGB    int64  `json:"totalGB"`
	ExpiryTime int64  `json:"expiryTime"`
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
	ServerNames  []string        `json:"serverNames"`
	PrivateKey   string          `json:"privateKey"`
	MinClientVer string          `json:"minClientVer"`
	ShortIDs     []string        `json:"shortIds"`
	Settings     struct {
		PublicKey   string `json:"publicKey"`
		Fingerprint string `json:"fingerprint"`
		ServerName  string `json:"serverName"`
		SpiderX     string `json:"spiderX"`
	} `json:"settings"`
}

// TargetString returns target (or the legacy dest) as a string; a bare
// number means a local port.
func (r *RealitySettings) TargetString() string {
	raw := r.Target
	if len(raw) == 0 || string(raw) == "null" || string(raw) == `""` {
		raw = r.Dest
	}
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

// TLSSettings is the part of tlsSettings the checks use.
type TLSSettings struct {
	ServerName   string    `json:"serverName"`
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
func (ib *Inbound) label() string {
	r := ib.Remark
	if r == "" {
		r = ib.Tag
	}
	return fmt.Sprintf("inbound #%d %q (%s, port %d)", ib.ID, r, ib.Protocol, ib.Port)
}

// local reports whether the inbound runs on this panel's own Xray (not on a node).
func (ib *Inbound) local() bool { return ib.NodeID == nil }

func (s *Snapshot) skipped(section string) (Finding, bool) {
	if msg, ok := s.Errors[section]; ok {
		return Finding{Severity: Info, Message: "skipped: could not read " + section + " (" + msg + ")"}, true
	}
	return Finding{}, false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
