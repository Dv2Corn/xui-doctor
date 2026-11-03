package checks

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// checkReality validates REALITY inbounds the way Xray-core's config loader
// does (infra/conf/transport_security.go) and, with --local or
// --dial-targets, checks the target from where the tool runs.
func checkReality(s *Snapshot) []Finding {
	if f, ok := s.skipped("inbounds"); ok {
		return []Finding{f}
	}
	var out []Finding
	for i := range s.Inbounds {
		ib := &s.Inbounds[i]
		if ib.Stream.Security != "reality" {
			continue
		}
		if ib.ParseError != "" {
			out = append(out, Finding{Severity: Warn, Subject: ib.label(), Message: "cannot parse inbound JSON: " + ib.ParseError})
			continue
		}
		r := ib.Stream.RealitySettings
		if r == nil {
			out = append(out, Finding{Severity: Critical, Subject: ib.label(), Message: "security is reality but realitySettings is missing",
				Fix: "Open the inbound, re-select REALITY and save."})
			continue
		}
		sev := Critical
		if !ib.Enable {
			sev = Warn // a disabled inbound does not stop Xray today, but will when enabled
		}
		bad := func(msg, fix string) {
			out = append(out, Finding{Severity: sev, Subject: ib.label(), Message: msg + " (Xray refuses to start with this inbound)", Fix: fix})
		}
		target := r.TargetString()
		if target == "" {
			bad(`empty "target" (dest)`, "Set the target to a TLS 1.3 site, e.g. example.com:443.")
		}
		if len(r.ServerNames) == 0 {
			bad(`empty "serverNames"`, "Add the domain(s) the target serves, e.g. the target's host name.")
		}
		switch {
		case strings.TrimSpace(r.PrivateKey) == "":
			bad(`empty "privateKey"`, "Generate a new X25519 key pair in the inbound form (clients need the new public key).")
		default:
			if k, err := base64.RawURLEncoding.DecodeString(r.PrivateKey); err != nil || len(k) != 32 {
				bad(`"privateKey" is not a 32-byte base64url X25519 key`, "Generate a new X25519 key pair in the inbound form.")
			}
		}
		if len(r.ShortIDs) == 0 {
			bad(`empty "shortIds"`, `Add at least one short ID (an empty string "" is allowed as one of them).`)
		}
		for i, sid := range r.ShortIDs {
			if len(sid) > 16 {
				bad(fmt.Sprintf("shortIds[%d] is longer than 16 hex characters", i), "Use 0-16 hex characters, an even count.")
				continue
			}
			if _, err := hex.DecodeString(sid); err != nil {
				bad(fmt.Sprintf("shortIds[%d] is not an even-length hex string", i), "Use 0-16 hex characters, an even count.")
			}
		}
		if strings.TrimSpace(r.Settings.PublicKey) == "" && strings.TrimSpace(r.PrivateKey) != "" {
			out = append(out, Finding{Severity: Warn, Subject: ib.label(),
				Message: "the public key for share links is empty, so links carry no pbk and Xray clients refuse them (empty \"password\")",
				Fix:     "Open the inbound and regenerate or re-save the key pair."})
		}
		if r.Show {
			out = append(out, Finding{Severity: Info, Subject: ib.label(),
				Message: `REALITY "show" (debug output) is on`, Fix: "Turn it off unless you are debugging."})
		}
		if ib.Enable && (s.Dial || s.Local) && s.Probe != nil && target != "" && len(r.ServerNames) > 0 {
			out = append(out, dialTarget(s, ib, target, r.ServerNames)...)
		}
	}
	return out
}

func dialTarget(s *Snapshot, ib *Inbound, target string, names []string) []Finding {
	addr := target
	if _, _, err := net.SplitHostPort(target); err != nil {
		if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "@") {
			return []Finding{{Severity: Info, Subject: ib.label(), Message: "target is a unix socket; not dialed"}}
		}
		if isAllDigits(target) {
			addr = "127.0.0.1:" + target
		} else {
			addr = net.JoinHostPort(target, "443")
		}
	}
	from := "from the panel host"
	if !s.Local {
		from = "from where xui-doctor runs (not necessarily the panel host)"
	}
	var out []Finding
	for _, sn := range names {
		if sn == "" || strings.HasPrefix(sn, "*") {
			continue
		}
		res, err := s.Probe.DialTLS(addr, sn)
		subj := ib.label() + " target " + addr + " sni " + sn
		if err != nil {
			out = append(out, Finding{Severity: Critical, Subject: subj,
				Message: "TLS handshake with the target failed " + from + ": " + err.Error(),
				Fix:     "Pick a target that answers TLS 1.3 for this name from the server; REALITY copies its handshake."})
			continue
		}
		if res.Version != tls.VersionTLS13 {
			out = append(out, Finding{Severity: Critical, Subject: subj, Message: "target does not negotiate TLS 1.3 " + from,
				Fix: "REALITY needs a TLS 1.3 target; choose another site."})
		}
		if res.ALPN != "h2" {
			out = append(out, Finding{Severity: Warn, Subject: subj, Message: fmt.Sprintf("target did not select h2 (ALPN %q) %s", res.ALPN, from),
				Fix: "Prefer a target that supports HTTP/2; browsers fingerprints offer h2."})
		}
		if res.VerifyError != nil && res.UnknownRoot {
			out = append(out, Finding{Severity: Info, Subject: subj,
				Message: "target certificate chain is not trusted by this machine's CA store (" + res.VerifyError.Error() + "); name not checked",
				Fix:     "Install the ca-certificates package where xui-doctor runs, then run again."})
		} else if res.VerifyError != nil {
			out = append(out, Finding{Severity: Warn, Subject: subj,
				Message: "target certificate does not verify for this server name " + from + ": " + res.VerifyError.Error(),
				Fix:     "List only names the target's certificate covers in serverNames."})
		}
	}
	if len(out) == 0 {
		out = append(out, Finding{Severity: OK, Subject: ib.label(), Message: "target " + addr + " answers TLS 1.3 + h2 with a valid certificate " + from})
	}
	return out
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
