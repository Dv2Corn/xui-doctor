package checks

import (
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/Dv2Corn/xui-doctor/internal/i18n"
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
	host   bool   // a subscription host, not the inbound itself
	remark string // the host's remark
	fp     string
	mihomo bool // host sets mihomoX25519
}

func checkXrayCompat(s *Snapshot) []Finding {
	var out []Finding
	x := s.Status.Xray
	switch strings.ToLower(x.State) {
	case "running", "":
	default:
		msg := strings.TrimSpace(strings.SplitN(x.ErrorMsg, "\n", 2)[0])
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		m := i18n.T("xray.not_running", x.State)
		if msg != "" {
			m = i18n.T("xray.not_running_msg", x.State, msg)
		}
		out = append(out, newFinding(Critical, i18n.T("subj.xray"), m, i18n.T("xray.not_running.fix")))
	}

	xv, ok := version.Parse(x.Version)
	if !ok {
		return append(out, newFinding(Info, i18n.T("subj.xray"), i18n.T("xray.bad_version", x.Version), i18n.Text{}))
	}

	if s.Inbounds == nil {
		if f, ok := s.skipped("inbounds"); ok {
			if version.AtLeast(xv, xrayMLKEMRequired) {
				return append(out, newFinding(Warn, i18n.T("subj.xray"), i18n.T("xray.mlkem_unread", xv.String()),
					i18n.T("xray.mlkem_unread.fix")), f)
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
		out = append(out, newFinding(Info, i18n.T("subj.nodes"),
			i18n.T("xray.on_nodes", len(onNodes), i18n.Plural("n.inbound_runs", len(onNodes))), i18n.Text{}))
	}
	if len(reality) == 0 {
		return append(out, newFinding(OK, i18n.T("subj.xray"), i18n.T("xray.no_reality", xv.String()), i18n.Text{}))
	}

	switch {
	case version.AtLeast(xv, xrayMLKEMRequired):
		out = append(out, mlkemFindings(s, xv, reality)...)
	case version.AtLeast(xv, xrayMinClientVerDefault):
		warned := 0
		for _, ib := range reality {
			if v := ib.Stream.RealitySettings.MinClientVer; v != "" && ValidClientVer(v) {
				continue
			}
			out = append(out, newFinding(Warn, ib.label(), i18n.T("xray.min_client_ver", xv.String()), i18n.T("xray.min_client_ver.fix")))
			warned++
		}
		if warned == 0 {
			out = append(out, newFinding(OK, i18n.T("subj.xray"), i18n.T("xray.min_client_ver_set", xv.String()), i18n.Text{}))
		}
	default:
		out = append(out, newFinding(OK, i18n.T("subj.xray"), i18n.T("xray.compatible", xv.String()), i18n.Text{}))
	}
	return out
}

func mlkemFindings(s *Snapshot, xv version.V, reality []*Inbound) []Finding {
	var out []Finding
	head := i18n.T("xray.mlkem_head", xv.String())
	pinFix := i18n.T("xray.pin_fix")

	var uses []fpUse
	byID := map[int]*Inbound{}
	for _, ib := range reality {
		byID[ib.ID] = ib
		uses = append(uses, fpUse{ib: ib, fp: ib.Stream.RealitySettings.Settings.Fingerprint})
	}
	uses = append(uses, hostUses(s, byID)...)

	refused := map[string][]i18n.Text{} // fp -> places
	random := map[string][]i18n.Text{}
	var mihomoHosts []i18n.Text
	for _, u := range uses {
		place := u.ib.label()
		if u.host {
			place = i18n.T("xray.host_place", u.remark, place)
		}
		if u.mihomo {
			mihomoHosts = append(mihomoHosts, place)
		}
		if u.host && u.fp == "" {
			continue // the host inherits the inbound's fingerprint
		}
		switch fpClass(u.fp) {
		case "refused":
			refused[u.fp] = append(refused[u.fp], place)
		case "random":
			random[u.fp] = append(random[u.fp], place)
		case "unknown":
			out = append(out, newFinding(Info, place, i18n.T("xray.fp_untested", u.fp), i18n.Text{}))
		}
	}
	for _, fp := range slices.Sorted(maps.Keys(refused)) {
		for _, place := range refused[fp] {
			out = append(out, newFinding(Critical, place, i18n.T("xray.fp_refused", head, fp),
				i18n.T("xray.fp_refused.fix", pinFix, i18n.T("xray.size_note"))))
		}
	}
	for _, fp := range slices.Sorted(maps.Keys(random)) {
		for _, place := range random[fp] {
			out = append(out, newFinding(Warn, place, i18n.T("xray.fp_random", head, fp), i18n.T("xray.fp_random.fix", pinFix)))
		}
	}
	for _, place := range mihomoHosts {
		out = append(out, newFinding(Critical, place, i18n.T("xray.mihomo_host", head), i18n.T("xray.mihomo_host.fix", pinFix)))
	}
	if f, ok := s.skipped("hosts"); ok && !notFound(s.Errors["hosts"]) {
		out = append(out, f) // host fingerprints were not checked; 404 is a 2.x panel without hosts
	}
	out = append(out, newFinding(Warn, i18n.T("subj.reality_clients"), i18n.T("xray.clients", head), i18n.T("xray.clients.fix", pinFix)))
	return out
}

func notFound(err error) bool {
	var ce *i18n.Error
	return errors.As(err, &ce) && ce.Text.ID == "api.http404"
}

// hostUses lists enabled subscription hosts that point at REALITY inbounds
// and keep REALITY security ("same" or "reality").
func hostUses(s *Snapshot, reality map[int]*Inbound) []fpUse {
	var out []fpUse
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
				out = append(out, fpUse{ib: ib, host: true, remark: h.Remark, fp: h.Fingerprint, mihomo: h.MihomoX25519})
			}
		}
	}
	return out
}
