package checks

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// transports returns the sockets ("tcp", "udp") an inbound binds, following
// the panel's own rules (internal/web/service/port_conflict.go in 3x-ui 3.11).
func transports(ib *Inbound) []string {
	switch strings.ToLower(ib.Protocol) {
	case "hysteria", "wireguard", "amneziawg", "tuic":
		return []string{"udp"}
	case "mtproto":
		return []string{"tcp"}
	case "masque":
		var st struct {
			TLSSettings struct {
				ALPN []string `json:"alpn"`
			} `json:"tlsSettings"`
		}
		_ = json.Unmarshal(ib.StreamSettings, &st)
		h2, h3 := slices.Contains(st.TLSSettings.ALPN, "h2"), slices.Contains(st.TLSSettings.ALPN, "h3")
		var out []string
		if h2 {
			out = append(out, "tcp")
		}
		if !h2 || h3 {
			out = append(out, "udp")
		}
		return out
	}
	tcp, udp := true, false
	switch strings.ToLower(ib.Stream.Network) {
	case "kcp", "quic":
		tcp, udp = false, true
	}
	var st map[string]any
	if json.Unmarshal(ib.Settings, &st) == nil {
		switch strings.ToLower(ib.Protocol) {
		case "shadowsocks", "tunnel":
			key := "network"
			if strings.ToLower(ib.Protocol) == "tunnel" {
				key = "allowedNetwork"
			}
			if n, ok := st[key].(string); ok && n != "" {
				tcp, udp = false, false
				for _, part := range strings.Split(n, ",") {
					switch strings.TrimSpace(part) {
					case "tcp":
						tcp = true
					case "udp":
						udp = true
					}
				}
			}
		case "mixed":
			if on, _ := st["udp"].(bool); on {
				udp = true
			}
		}
	}
	var out []string
	if tcp || !udp {
		out = append(out, "tcp")
	}
	if udp {
		out = append(out, "udp")
	}
	return out
}

func isWildcard(listen string) bool {
	switch strings.TrimSpace(listen) {
	case "", "0.0.0.0", "::", "::0", "[::]":
		return true
	}
	return false
}

func bindsPort(ib *Inbound) bool {
	l := strings.TrimSpace(ib.Listen)
	return ib.Port > 0 && !strings.HasPrefix(l, "/") && !strings.HasPrefix(l, "@") && strings.ToLower(ib.Protocol) != "tun"
}

type binder struct {
	name   string
	listen string
}

func overlaps(a, b string) bool {
	return isWildcard(a) || isWildcard(b) || strings.TrimSpace(a) == strings.TrimSpace(b)
}

// checkPorts finds enabled inbounds (and the panel / subscription server)
// that would bind the same port and transport on the same host.
func checkPorts(s *Snapshot) []Finding {
	if f, ok := s.skipped("inbounds"); ok {
		return []Finding{f}
	}
	type key struct {
		node  int // -1 = this host
		proto string
		port  int
	}
	groups := map[key][]binder{}
	for i := range s.Inbounds {
		ib := &s.Inbounds[i]
		if !ib.Enable || !bindsPort(ib) {
			continue
		}
		node := -1
		if ib.NodeID != nil {
			node = *ib.NodeID
		}
		for _, proto := range transports(ib) {
			k := key{node, proto, ib.Port}
			groups[k] = append(groups[k], binder{name: ib.label(), listen: ib.Listen})
		}
	}
	if s.Settings != nil {
		if s.Settings.WebPort > 0 {
			k := key{-1, "tcp", s.Settings.WebPort}
			groups[k] = append(groups[k], binder{name: "the panel web server", listen: s.Settings.WebListen})
		}
		if s.Settings.SubEnable && s.Settings.SubPort > 0 && s.Settings.SubPort != s.Settings.WebPort {
			k := key{-1, "tcp", s.Settings.SubPort}
			groups[k] = append(groups[k], binder{name: "the subscription server", listen: s.Settings.SubListen})
		}
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		return keys[i].proto < keys[j].proto
	})
	var out []Finding
	for _, k := range keys {
		g := groups[k]
		for i := 0; i < len(g); i++ {
			for j := i + 1; j < len(g); j++ {
				if !overlaps(g[i].listen, g[j].listen) {
					continue
				}
				where := ""
				if k.node >= 0 {
					where = fmt.Sprintf(" on node #%d", k.node)
				}
				out = append(out, Finding{Severity: Critical, Subject: fmt.Sprintf("%s/%d%s", k.proto, k.port, where),
					Message: g[i].name + " and " + g[j].name + " use the same port; only one can bind it and Xray (or the panel) fails to start",
					Fix:     "Move one of them to another port, or bind them to different listen addresses."})
			}
		}
	}
	if s.Local && s.Probe != nil {
		out = append(out, listeningFindings(s)...)
	}
	return out
}

func listeningFindings(s *Snapshot) []Finding {
	socks, err := s.Probe.Listening()
	if err != nil {
		return []Finding{{Severity: Info, Subject: "sockets", Message: "cannot list listening sockets: " + err.Error()}}
	}
	if s.Status != nil && !strings.EqualFold(s.Status.Xray.State, "running") && s.Status.Xray.State != "" {
		return nil // already reported by the xray check
	}
	var out []Finding
	for i := range s.Inbounds {
		ib := &s.Inbounds[i]
		if !ib.Enable || !ib.local() || !bindsPort(ib) {
			continue
		}
		for _, proto := range transports(ib) {
			k := fmt.Sprintf("%s/%d", proto, ib.Port)
			if !socks[k] {
				out = append(out, Finding{Severity: Warn, Subject: ib.label(),
					Message: "nothing listens on " + k + " on this host although the inbound is enabled",
					Fix:     "Check the Xray log for a bind error; restart Xray from the panel."})
			}
		}
	}
	return out
}
