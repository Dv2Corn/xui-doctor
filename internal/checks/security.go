package checks

import (
	"net"
	"net/url"
	"strings"

	"github.com/Dv2Corn/xui-doctor/internal/i18n"
)

// checkSecurity reports the panel's exposure. It never guesses passwords:
// default credentials are flagged only when the operator ran the tool with them.
func checkSecurity(s *Snapshot) []Finding {
	var out []Finding
	u, _ := url.Parse(s.PanelURL)
	if s.DefaultCredentials {
		out = append(out, newFinding(Critical, i18n.T("subj.login"),
			i18n.T("security.default_login"), i18n.T("security.default_login.fix")))
	}
	if u != nil && u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		out = append(out, newFinding(Critical, i18n.T("subj.transport"),
			i18n.T("security.plain_http_url"), i18n.T("security.plain_http_url.fix")))
	}
	st := s.Settings
	if st == nil {
		if f, ok := s.skipped("settings"); ok {
			out = append(out, f)
		}
		if u != nil && u.Host != "" && strings.Trim(u.Path, "/") == "" {
			out = append(out, basePathFinding())
		}
		return out
	}
	if strings.Trim(st.WebBasePath, "/") == "" {
		out = append(out, basePathFinding())
	}
	if st.WebPort == 2053 {
		out = append(out, newFinding(Info, i18n.T("subj.panel_port"),
			i18n.T("security.default_port"), i18n.T("security.default_port.fix")))
	}
	if st.SubEnable && pathOf(st.SubPath, st.SubURI) == "/sub/" {
		out = append(out, newFinding(Info, i18n.T("subj.sub_path"),
			i18n.T("security.default_sub_path"), i18n.T("security.default_sub_path.fix")))
	}
	if st.SubJSONEnable && pathOf(st.SubJSONPath, st.SubJSONURI) == "/json/" {
		out = append(out, newFinding(Info, i18n.T("subj.sub_path"),
			i18n.T("security.default_json_path"), i18n.T("security.default_json_path.fix")))
	}
	plain := strings.TrimSpace(st.WebCertFile) == "" || strings.TrimSpace(st.WebKeyFile) == ""
	if plain && !isLoopbackHost(st.WebListen) {
		var listen any = st.WebListen
		if st.WebListen == "" {
			listen = i18n.T("security.all_addresses")
		}
		out = append(out, newFinding(Warn, i18n.T("subj.panel_listener"),
			i18n.T("security.plain_http_listen", listen), i18n.T("security.plain_http_listen.fix")))
	}
	if !st.TwoFactorEnable {
		out = append(out, newFinding(Warn, i18n.T("subj.login"),
			i18n.T("security.no_2fa"), i18n.T("security.no_2fa.fix")))
	}
	if st.HasTgBotToken {
		msg := i18n.T("security.tg_bot_disabled")
		if st.TgBotEnable {
			msg = i18n.T("security.tg_bot_enabled")
		}
		out = append(out, newFinding(Info, i18n.T("subj.tg_bot"), msg, i18n.T("security.tg_bot.fix")))
	}
	return out
}

func basePathFinding() Finding {
	return newFinding(Warn, i18n.T("subj.base_path"), i18n.T("security.root_path"), i18n.T("security.root_path.fix"))
}

// pathOf mirrors the panel's own warning: a configured URI wins over the path.
func pathOf(path, uri string) string {
	if uri != "" {
		if u, err := url.Parse(uri); err == nil {
			return u.Path
		}
	}
	return path
}

func isLoopbackHost(h string) bool {
	h = strings.Trim(strings.TrimSpace(h), "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
