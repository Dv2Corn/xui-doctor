package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Dv2Corn/xui-doctor/internal/version"
)

// Version boundaries of the official Xray-core REALITY server, verified
// against the release tags (see README "Why the Xray check exists"):
//
//   - 26.7.11: REALITY servers default "minClientVer" to 26.3.27
//     (Xray-core af7eb680), so clients that do not send an Xray version
//     (sing-box, mihomo) and Xray older than 26.3.27 are refused unless the
//     inbound sets minClientVer itself.
//   - 26.9.8: XTLS/REALITY 8cdf7bf9 "Reject outdated/strange Client Hello that
//     doesn't have X25519MLKEM768 before optional X25519"; the same release
//     comments the minClientVer default out again. The 26.9.8 tag was later
//     deleted upstream; 26.9.9 is the first published release with it.
var (
	xrayMinClientVerDefault = version.MustParse("26.7.11")
	xrayMLKEMRequired       = version.MustParse("26.9.8")
)

// fpClass says how a uTLS fingerprint fares against a REALITY server that
// requires X25519MLKEM768. Measured with Xray 26.6.27 and 26.10.31 clients
// against official 26.9.9 and 26.10.31 servers.
func fpClass(fp string) string {
	switch strings.ToLower(strings.TrimSpace(fp)) {
	case "", "chrome", "firefox", "safari":
		return "ok" // empty: Xray clients treat it as chrome
	case "ios", "android", "edge", "360", "qq":
		return "refused"
	case "random", "randomized", "randomizednoalpn":
		return "random"
	default:
		return "unknown"
	}
}

type fpUse struct {
	ib     *Inbound
	where  string // "inbound" or `host "remark"`
	fp     string
	mihomo bool // host sets mihomoX25519
}

func checkXrayCompat(s *Snapshot) []Finding {
	var out []Finding
	if s.Status == nil {
		if f, ok := s.skipped("status"); ok {
			return []Finding{f}
		}
		return nil
	}
	x := s.Status.Xray
	switch strings.ToLower(x.State) {
	case "running", "":
	default:
		msg := strings.TrimSpace(strings.SplitN(x.ErrorMsg, "\n", 2)[0])
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		f := Finding{Severity: Critical, Subject: "xray", Message: "Xray is not running (state: " + x.State + ")",
			Fix: "Open the panel's overview and check the Xray log; restart Xray after fixing the config."}
		if msg != "" {
			f.Message += ": " + msg
		}
		out = append(out, f)
	}

	xv, ok := version.Parse(x.Version)
	if !ok {
		return append(out, Finding{Severity: Info, Subject: "xray",
			Message: fmt.Sprintf("cannot parse the Xray version %q; REALITY compatibility not assessed", x.Version)})
	}

	if s.Inbounds == nil {
		if f, ok := s.skipped("inbounds"); ok {
			if version.AtLeast(xv, xrayMLKEMRequired) {
				return append(out, Finding{Severity: Warn, Subject: "xray",
					Message: "Xray " + xv.String() + " (>= 26.9.8) refuses REALITY ClientHellos without an X25519MLKEM768 key share " +
						"(fp=ios/edge/qq links, sing-box clients); inbound fingerprints could not be read with these credentials",
					Fix: "Run again with an admin-scope token or the panel login to see which inbounds are affected."}, f)
			}
			return append(out, f)
		}
	}
	var reality, onNodes []*Inbound
	for i := range s.Inbounds {
		ib := &s.Inbounds[i]
		if !ib.Enable || ib.Stream.Security != "reality" || ib.Stream.RealitySettings == nil {
			continue
		}
		if !ib.local() {
			onNodes = append(onNodes, ib)
			continue
		}
		reality = append(reality, ib)
	}
	if len(onNodes) > 0 {
		out = append(out, Finding{Severity: Info, Subject: "nodes",
			Message: fmt.Sprintf("%d REALITY %s on remote nodes: their Xray version is not reported here; run xui-doctor against each node",
				len(onNodes), plural(len(onNodes), "inbound runs", "inbounds run"))})
	}
	if len(reality) == 0 {
		return append(out, Finding{Severity: OK, Subject: "xray", Message: "Xray " + xv.String() + "; no enabled REALITY inbounds on this panel's core"})
	}

	switch {
	case version.AtLeast(xv, xrayMLKEMRequired):
		out = append(out, mlkemFindings(s, xv, reality)...)
	case version.AtLeast(xv, xrayMinClientVerDefault):
		warned := 0
		for _, ib := range reality {
			if strings.TrimSpace(ib.Stream.RealitySettings.MinClientVer) != "" {
				continue
			}
			out = append(out, Finding{Severity: Warn, Subject: ib.label(),
				Message: "Xray " + xv.String() + " defaults REALITY minClientVer to 26.3.27: sing-box clients (Hiddify, Karing, NekoBox...), " +
					"mihomo/Clash clients and Xray clients older than 26.3.27 are refused",
				Fix: `Set "minClientVer" explicitly on the inbound (e.g. "0.0.0" accepts every client), or switch Xray to 26.6.27.`})
			warned++
		}
		if warned == 0 {
			out = append(out, Finding{Severity: OK, Subject: "xray", Message: "Xray " + xv.String() + ": REALITY inbounds set minClientVer explicitly"})
		}
	default:
		out = append(out, Finding{Severity: OK, Subject: "xray",
			Message: "Xray " + xv.String() + " accepts REALITY ClientHellos with or without ML-KEM (sing-box, mihomo and fp=ios clients work)"})
	}
	return out
}

func mlkemFindings(s *Snapshot, xv version.V, reality []*Inbound) []Finding {
	var out []Finding
	head := "Xray " + xv.String() + " (>= 26.9.8) refuses REALITY ClientHellos without an X25519MLKEM768 key share"
	pinFix := "or pin Xray 26.6.27 in the panel's Xray version switcher (keeps old clients working, loses newer core fixes)"
	sizeNote := "ML-KEM ClientHellos are ~1.5-1.9 KB and need two TCP segments; a few mobile networks drop those."

	var uses []fpUse
	byID := map[int]*Inbound{}
	for _, ib := range reality {
		byID[ib.ID] = ib
		uses = append(uses, fpUse{ib: ib, where: "inbound", fp: ib.Stream.RealitySettings.Settings.Fingerprint})
	}
	for _, h := range hostRefs(s, byID) {
		uses = append(uses, fpUse{ib: h.ib, where: fmt.Sprintf("host %q", h.remark), fp: h.fp, mihomo: h.mihomo})
	}

	refused := map[string][]string{} // fp -> places
	random := map[string][]string{}
	var mihomoHosts []string
	for _, u := range uses {
		place := u.ib.label()
		if u.where != "inbound" {
			place = u.where + " -> " + place
		}
		if u.mihomo {
			mihomoHosts = append(mihomoHosts, place)
		}
		if u.where != "inbound" && u.fp == "" {
			continue // the host inherits the inbound's fingerprint
		}
		switch fpClass(u.fp) {
		case "refused":
			refused[u.fp] = append(refused[u.fp], place)
		case "random":
			random[u.fp] = append(random[u.fp], place)
		case "unknown":
			out = append(out, Finding{Severity: Info, Subject: place,
				Message: fmt.Sprintf("fingerprint %q was not tested against an ML-KEM-only REALITY server", u.fp)})
		}
	}
	for _, fp := range sortedKeys(refused) {
		for _, place := range refused[fp] {
			out = append(out, Finding{Severity: Critical, Subject: place,
				Message: head + "; share links here use fp=" + fp + ", which has none, so clients using them cannot connect",
				Fix:     "Set the uTLS fingerprint to chrome, firefox or safari and let clients refresh the subscription, " + pinFix + ". " + sizeNote})
		}
	}
	for _, fp := range sortedKeys(random) {
		for _, place := range random[fp] {
			out = append(out, Finding{Severity: Warn, Subject: place,
				Message: head + "; fp=" + fp + " picks a hello per connection, and some picks have no ML-KEM share, so connections fail at random",
				Fix:     "Use chrome, firefox or safari instead, " + pinFix + "."})
		}
	}
	for _, place := range mihomoHosts {
		out = append(out, Finding{Severity: Critical, Subject: place,
			Message: head + `; this host has "Mihomo X25519" on, so its Clash subscription turns ML-KEM off and mihomo clients are refused`,
			Fix:     `Turn "Mihomo X25519" off for this host (it only makes sense with Xray < 26.9.8), ` + pinFix + "."})
	}
	out = append(out, Finding{Severity: Warn, Subject: "REALITY clients",
		Message: head + ": sing-box based clients (sing-box, Hiddify, Karing, NekoBox; tested 1.12.12 and 1.14.4) cannot connect with any fingerprint; " +
			"mihomo/Clash clients connect only with reality-opts support-x25519mlkem768: true and a chrome/firefox/safari fingerprint " +
			"(the panel's Clash subscription sets it; imported vless:// links and hand-written configs usually do not)",
		Fix: "Tell sing-box/Hiddify users to use an Xray-based client or the Clash subscription in a mihomo client, " + pinFix + "."})
	return out
}

type hostRef struct {
	ib     *Inbound
	remark string
	fp     string
	mihomo bool
}

// hostRefs lists enabled subscription hosts that point at REALITY inbounds
// and keep REALITY security ("same" or "reality").
func hostRefs(s *Snapshot, reality map[int]*Inbound) []hostRef {
	var out []hostRef
	for _, h := range s.Hosts {
		if h.IsDisabled {
			continue
		}
		sec := strings.ToLower(h.Security)
		if sec != "" && sec != "same" && sec != "reality" {
			continue
		}
		for _, id := range h.InboundIDs {
			if ib, ok := reality[id]; ok {
				out = append(out, hostRef{ib: ib, remark: h.Remark, fp: h.Fingerprint, mihomo: h.MihomoX25519})
			}
		}
	}
	return out
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
