package checks

import (
	"fmt"
	"sort"
	"strings"
)

// checkClients looks at per-client state the panel keeps in clientStats
// (client_traffics) and settings.clients[].
//
// Since 3x-ui 3.x a client (unique e-mail) may be attached to several
// inbounds on purpose, so the same e-mail on two inbounds is not reported.
func checkClients(s *Snapshot) []Finding {
	if f, ok := s.skipped("inbounds"); ok {
		return []Finding{f}
	}
	nowMs := s.Now.UnixMilli()
	var out []Finding
	expired, exhausted := map[string]bool{}, map[string]bool{}
	limited := map[string]bool{}
	for i := range s.Inbounds {
		ib := &s.Inbounds[i]
		if !ib.Enable {
			continue
		}
		for _, st := range ib.ClientStats {
			if !st.Enable || st.Email == "" {
				continue
			}
			if st.ExpiryTime > 0 && st.ExpiryTime <= nowMs {
				expired[st.Email] = true
			}
			if st.Total > 0 && st.Up+st.Down >= st.Total {
				exhausted[st.Email] = true
			}
		}
		// Xray keys VLESS/VMess users by UUID (and Trojan/SS by password)
		// inside one inbound: two e-mails with one secret are one user to Xray.
		seen := map[string]string{}
		for _, c := range ib.Clients {
			if c.LimitIP > 0 && c.Enable {
				limited[c.Email] = true
			}
			sec := clientSecret(ib.Protocol, c)
			if sec == "" {
				continue
			}
			if other, ok := seen[sec]; ok && other != c.Email {
				out = append(out, Finding{Severity: Warn, Subject: ib.label(),
					Message: fmt.Sprintf("clients %q and %q share one credential (UUID/password); Xray treats them as one user, so traffic, limits and removal hit the wrong client", other, c.Email),
					Fix:     "Give one of the clients a new UUID/password and send it the new link."})
				continue
			}
			seen[sec] = c.Email
		}
	}
	if len(expired) > 0 {
		out = append(out, Finding{Severity: Warn, Subject: "clients",
			Message: fmt.Sprintf("%d %s past expiry but still enabled in the panel's traffic table: %s", len(expired), plural(len(expired), "client is", "clients are"), list(expired)),
			Fix:     "The panel's traffic job disables these periodically while Xray is running; if they stay enabled, check that Xray runs and read the panel log."})
	}
	if len(exhausted) > 0 {
		out = append(out, Finding{Severity: Warn, Subject: "clients",
			Message: fmt.Sprintf("%d %s used up the traffic quota but still enabled: %s", len(exhausted), plural(len(exhausted), "client has", "clients have"), list(exhausted)),
			Fix:     "Same as above: the panel's traffic job should disable them; check the panel log."})
	}
	if len(limited) > 0 {
		out = append(out, ipLimitFinding(s, limited))
	}
	return out
}

func ipLimitFinding(s *Snapshot, limited map[string]bool) Finding {
	n := len(limited)
	base := fmt.Sprintf("%d %s an IP limit (limitIp)", n, plural(n, "client has", "clients have"))
	how := "the panel counts each client's source IPs from Xray's online stats and bans extra IPs with fail2ban (Windows: drops the connections); " +
		"clients behind CGNAT or switching networks can trip it"
	if s.Fail2ban == nil {
		return Finding{Severity: Info, Subject: "clients", Message: base + "; " + how + ". fail2ban status not readable"}
	}
	f := s.Fail2ban
	if !f.Windows && !(f.Enabled && f.Installed && f.Usable) {
		return Finding{Severity: Warn, Subject: "clients",
			Message: base + " but fail2ban is not usable on the panel host (enabled=" + yn(f.Enabled) + ", installed=" + yn(f.Installed) + ", usable=" + yn(f.Usable) + "), so the limit is not enforced",
			Fix:     "Install/enable fail2ban (the x-ui (or still-ui) shell menu -> Fail2ban / IP Limit), or remove the limits so nobody relies on them."}
	}
	return Finding{Severity: Info, Subject: "clients", Message: base + "; " + how}
}

func clientSecret(protocol string, c Client) string {
	switch strings.ToLower(protocol) {
	case "vless", "vmess":
		return strings.ToLower(strings.TrimSpace(c.ID))
	case "trojan", "shadowsocks":
		return c.Password
	case "hysteria":
		return c.Auth
	}
	return ""
}

func list(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 10 {
		return strings.Join(keys[:10], ", ") + fmt.Sprintf(" and %d more", len(keys)-10)
	}
	return strings.Join(keys, ", ")
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
