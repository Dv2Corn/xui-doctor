package checks

import (
	"net"
	"net/url"
	"strings"
)

// checkSecurity reports the panel's exposure. It never guesses passwords:
// default credentials are flagged only when the operator ran the tool with them.
func checkSecurity(s *Snapshot) []Finding {
	var out []Finding
	u, _ := url.Parse(s.PanelURL)
	if s.DefaultCredentials {
		out = append(out, Finding{Severity: Critical, Subject: "login",
			Message: "the panel accepts the default admin/admin login",
			Fix:     "Change the username and password (Settings -> Authentication -> Admin credentials)."})
	}
	if u != nil && u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		out = append(out, Finding{Severity: Critical, Subject: "transport",
			Message: "the panel is reached over plain HTTP on a non-loopback address; the login and session cookie travel unencrypted",
			Fix:     "Give the panel a certificate, or reach it only through an SSH tunnel (ssh -L) or a TLS reverse proxy."})
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
		out = append(out, Finding{Severity: Info, Subject: "panel port",
			Message: "the panel uses the default port 2053, which scanners probe for 3x-ui",
			Fix:     "Pick a random port (Settings -> General -> Listen Port) and open it in the firewall instead."})
	}
	if st.SubEnable && pathOf(st.SubPath, st.SubURI) == "/sub/" {
		out = append(out, Finding{Severity: Info, Subject: "subscription path",
			Message: `the subscription path is the default "/sub/", so the subscription server is easy to fingerprint`,
			Fix:     "Set a random subscription path (Settings -> Subscription); clients then need the new link."})
	}
	if st.SubJSONEnable && pathOf(st.SubJSONPath, st.SubJSONURI) == "/json/" {
		out = append(out, Finding{Severity: Info, Subject: "subscription path",
			Message: `the JSON subscription path is the default "/json/"`,
			Fix:     "Set a random JSON subscription path; clients then need the new link."})
	}
	plain := strings.TrimSpace(st.WebCertFile) == "" || strings.TrimSpace(st.WebKeyFile) == ""
	if plain && !isLoopbackHost(st.WebListen) {
		listen := st.WebListen
		if listen == "" {
			listen = "all addresses"
		}
		out = append(out, Finding{Severity: Warn, Subject: "panel listener",
			Message: "the panel serves plain HTTP on " + listen + "; fine behind a TLS proxy or firewall, otherwise anyone on the path sees the login",
			Fix:     "Set a panel certificate, or set the listen IP to 127.0.0.1 and use an SSH tunnel."})
	}
	if !st.TwoFactorEnable {
		out = append(out, Finding{Severity: Warn, Subject: "login",
			Message: "two-factor authentication is off",
			Fix:     "Enable it in Settings -> Authentication -> Two-factor authentication."})
	}
	if st.HasTgBotToken {
		state := "configured but disabled"
		if st.TgBotEnable {
			state = "enabled"
		}
		out = append(out, Finding{Severity: Info, Subject: "telegram bot",
			Message: "a Telegram bot token is " + state + "; the bot can manage clients and send database backups to its admin chats",
			Fix:     "Keep the token secret and the admin chat ID list short; revoke it in @BotFather if it leaked."})
	}
	return out
}

func basePathFinding() Finding {
	return Finding{Severity: Warn, Subject: "base path",
		Message: `the panel's web base path is "/", so scanners find the login page at the root`,
		Fix:     "Set a random URI path (Settings -> General -> URI Path) and use the new panel URL."}
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
