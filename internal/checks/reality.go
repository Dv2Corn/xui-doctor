package checks

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"

	"github.com/Dv2Corn/xui-doctor/internal/i18n"
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
			out = append(out, newFinding(Warn, ib.label(), i18n.T("reality.parse_error", ib.ParseError), i18n.Text{}))
			continue
		}
		r := ib.Stream.RealitySettings
		if r == nil {
			out = append(out, newFinding(Critical, ib.label(), i18n.T("reality.no_settings"), i18n.T("reality.no_settings.fix")))
			continue
		}
		sev := Critical
		if !ib.Enable {
			sev = Warn // a disabled inbound does not stop Xray today, but will when enabled
		}
		bad := func(msg, fix i18n.Text) {
			out = append(out, newFinding(sev, ib.label(), i18n.T("reality.refused", msg), fix))
		}
		target := r.TargetString()
		if target == "" {
			bad(i18n.T("reality.empty_target"), i18n.T("reality.empty_target.fix"))
		}
		if len(r.ServerNames) == 0 {
			bad(i18n.T("reality.empty_names"), i18n.T("reality.empty_names.fix"))
		}
		switch {
		case strings.TrimSpace(r.PrivateKey) == "":
			bad(i18n.T("reality.empty_key"), i18n.T("reality.empty_key.fix"))
		default:
			if k, err := base64.RawURLEncoding.DecodeString(r.PrivateKey); err != nil || len(k) != 32 {
				bad(i18n.T("reality.bad_key"), i18n.T("reality.bad_key.fix"))
			}
		}
		if len(r.ShortIDs) == 0 {
			bad(i18n.T("reality.empty_sids"), i18n.T("reality.empty_sids.fix"))
		}
		for i, sid := range r.ShortIDs {
			if len(sid) > 16 {
				bad(i18n.T("reality.sid_long", i), i18n.T("reality.sid.fix"))
				continue
			}
			if _, err := hex.DecodeString(sid); err != nil {
				bad(i18n.T("reality.sid_not_hex", i), i18n.T("reality.sid.fix"))
			}
		}
		if strings.TrimSpace(r.Settings.PublicKey) == "" && strings.TrimSpace(r.PrivateKey) != "" {
			out = append(out, newFinding(Warn, ib.label(), i18n.T("reality.no_pbk"), i18n.T("reality.no_pbk.fix")))
		}
		if r.Show {
			out = append(out, newFinding(Info, ib.label(), i18n.T("reality.show"), i18n.T("reality.show.fix")))
		}
		if ib.Enable && (s.Dial || s.Local) && s.Probe != nil && target != "" && len(r.ServerNames) > 0 {
			out = append(out, dialTarget(s, ib, target, r.ServerNames)...)
		}
	}
	return out
}

// dialTarget handshakes with the REALITY target for every server name. The
// target comes from the panel, so outside --local it is dialed only when it
// resolves to public addresses, at the address resolved once here, and the
// whole run makes at most MaxTargetProbes handshakes.
func dialTarget(s *Snapshot, ib *Inbound, target string, names []string) []Finding {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		switch {
		case strings.HasPrefix(target, "/") || strings.HasPrefix(target, "@"):
			return []Finding{newFinding(Info, ib.label(), i18n.T("reality.unix_target"), i18n.Text{})}
		case isAllDigits(target):
			host, port = "127.0.0.1", target
		default:
			host, port = target, "443"
		}
	}
	shown := net.JoinHostPort(host, port)
	from := i18n.T("reality.from_panel")
	if !s.Local {
		from = i18n.T("reality.from_here")
	}
	ip, skip := pickTargetIP(s, host)
	if skip.ID != "" {
		return []Finding{newFinding(Info, i18n.T("reality.subj_target", ib.label(), shown), i18n.T("reality.not_dialed", skip), i18n.Text{})}
	}
	addr := net.JoinHostPort(ip.String(), port)
	var out []Finding
	skipped := 0
	for _, sn := range names {
		if sn == "" || strings.HasPrefix(sn, "*") {
			continue
		}
		if s.probes >= MaxTargetProbes {
			skipped++
			continue
		}
		s.probes++
		res, err := s.Probe.DialTLS(addr, sn)
		subj := i18n.T("reality.subj_sni", ib.label(), shown, sn)
		if err != nil {
			out = append(out, newFinding(Critical, subj, i18n.T("reality.handshake_failed", from, err), i18n.T("reality.handshake_failed.fix")))
			continue
		}
		if res.Version != tls.VersionTLS13 {
			out = append(out, newFinding(Critical, subj, i18n.T("reality.no_tls13", from), i18n.T("reality.no_tls13.fix")))
		}
		if res.ALPN != "h2" {
			out = append(out, newFinding(Warn, subj, i18n.T("reality.no_h2", res.ALPN, from), i18n.T("reality.no_h2.fix")))
		}
		if res.VerifyError != nil && res.UnknownRoot {
			out = append(out, newFinding(Info, subj, i18n.T("reality.unknown_root", res.VerifyError), i18n.T("reality.unknown_root.fix")))
		} else if res.VerifyError != nil {
			out = append(out, newFinding(Warn, subj, i18n.T("reality.bad_cert", from, res.VerifyError), i18n.T("reality.bad_cert.fix")))
		}
	}
	if skipped > 0 {
		out = append(out, newFinding(Info, i18n.T("reality.subj_target", ib.label(), shown),
			i18n.T("reality.dial_cap", skipped, i18n.Plural("n.server_name", skipped), MaxTargetProbes), i18n.Text{}))
	}
	if len(out) == 0 {
		out = append(out, newFinding(OK, ib.label(), i18n.T("reality.target_ok", shown, ip.String(), from), i18n.Text{}))
	}
	return out
}

// pickTargetIP resolves host once and returns the address to dial, or why
// the target is skipped. Without --local, addresses that are not public
// (loopback, private, link-local, unspecified, multicast, CGNAT, ULA) are
// refused: the target comes from the panel and must not point the probe at
// the operator's own network.
func pickTargetIP(s *Snapshot, host string) (net.IP, i18n.Text) {
	var ips []net.IP
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		ips = []net.IP{ip}
	} else {
		var err error
		if ips, err = s.Probe.LookupIP(host); err != nil {
			return nil, i18n.T("reality.no_resolve", host, err)
		}
		if len(ips) == 0 {
			return nil, i18n.T("reality.no_address", host)
		}
	}
	if s.Local {
		return ips[0], i18n.Text{}
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, i18n.T("reality.non_public", host, ip.String())
		}
	}
	return ips[0], i18n.Text{}
}

// specialPrefixes are IANA special-purpose blocks (and documentation, test,
// CGNAT, multicast and translation ranges) that a target taken from panel
// data must not point at. NAT64 (64:ff9b::/96, 64:ff9b:1::/48) and 6to4
// (2002::/16) are refused as a whole, which also covers any private IPv4
// embedded in them.
var specialPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		"::/128", "::1/128", "100::/64", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2001:db8::/32",
		"2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// PublicAddr reports whether a is an ordinary public unicast address.
// IPv4-mapped IPv6 addresses are judged as the IPv4 address they carry.
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	for _, p := range specialPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func publicIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	return ok && PublicAddr(a)
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
