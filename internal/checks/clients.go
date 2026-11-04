package checks

import (
	"sort"
	"strings"

	"github.com/Dv2Corn/xui-doctor/internal/i18n"
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
				out = append(out, newFinding(Warn, ib.label(),
					i18n.T("clients.shared_secret", other, c.Email), i18n.T("clients.shared_secret.fix")))
				continue
			}
			seen[sec] = c.Email
		}
	}
	if len(expired) > 0 {
		out = append(out, newFinding(Warn, i18n.T("subj.clients"),
			i18n.T("clients.expired", len(expired), i18n.Plural("n.client_is", len(expired)), list(expired)),
			i18n.T("clients.expired.fix")))
	}
	if len(exhausted) > 0 {
		out = append(out, newFinding(Warn, i18n.T("subj.clients"),
			i18n.T("clients.exhausted", len(exhausted), i18n.Plural("n.client_has", len(exhausted)), list(exhausted)),
			i18n.T("clients.exhausted.fix")))
	}
	if len(limited) > 0 {
		out = append(out, ipLimitFinding(s, limited))
	}
	return out
}

func ipLimitFinding(s *Snapshot, limited map[string]bool) Finding {
	n := len(limited)
	base := i18n.T("clients.iplimit", n, i18n.Plural("n.client_has_limit", n))
	how := i18n.T("clients.iplimit.how")
	subj := i18n.T("subj.clients")
	if s.Fail2ban == nil {
		return newFinding(Info, subj, i18n.T("clients.iplimit.no_status", base, how), i18n.Text{})
	}
	f := s.Fail2ban
	if !f.Windows && !(f.Enabled && f.Installed && f.Usable) {
		return newFinding(Warn, subj, i18n.T("clients.iplimit.unenforced", base, yn(f.Enabled), yn(f.Installed), yn(f.Usable)),
			i18n.T("clients.iplimit.unenforced.fix"))
	}
	return newFinding(Info, subj, i18n.T("clients.iplimit.info", base, how), i18n.Text{})
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

func list(m map[string]bool) any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 10 {
		return i18n.T("list.more", strings.Join(keys[:10], ", "), len(keys)-10)
	}
	return strings.Join(keys, ", ")
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
