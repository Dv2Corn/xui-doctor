// Package report renders findings as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Dv2Corn/xui-doctor/internal/api"
	"github.com/Dv2Corn/xui-doctor/internal/checks"
	"github.com/Dv2Corn/xui-doctor/internal/i18n"
)

// Header describes the panel in the report.
type Header struct {
	Tool            string `json:"tool"`
	PanelURL        string `json:"panelUrl"`
	PanelKind       string `json:"panelKind"`
	PanelVersion    string `json:"panelVersion"`
	UpstreamVersion string `json:"upstreamVersion,omitempty"`
	XrayVersion     string `json:"xrayVersion"`
	Auth            string `json:"auth"`
	Local           bool   `json:"local"`
	DialTargets     bool   `json:"dialTargets"`
	// Lang is the language of text output; JSON output is always English.
	Lang i18n.Lang `json:"-"`
}

// JSON writes {"header":..., "worst":..., "findings":[...]}. The panel URL
// is written without its base path.
func JSON(w io.Writer, h Header, fs []checks.Finding) error {
	h.PanelURL = api.RedactURL(h.PanelURL)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(struct {
		Header   Header           `json:"header"`
		Worst    checks.Severity  `json:"worst"`
		Findings []checks.Finding `json:"findings"`
	}{h, checks.Worst(fs), fs})
}

// Clean drops characters that a terminal would interpret: C0 controls other
// than tab, DEL, C1 controls and bidirectional overrides/isolates. Remarks,
// e-mails, tags and server names come from the panel and may contain them.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return r
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f,
			r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return -1
		}
		return r
	}, s)
}

// Text writes findings grouped by severity, worst first, in h.Lang (English
// when empty). Every string is passed through Clean before it reaches the
// terminal. The panel URL is shown without its base path.
func Text(w io.Writer, h Header, fs []checks.Finding, showOK bool) {
	l := h.Lang
	if l == "" {
		l = i18n.EN
	}
	h = Header{Tool: Clean(h.Tool), PanelURL: Clean(api.RedactURL(h.PanelURL)), PanelKind: Clean(h.PanelKind),
		PanelVersion: Clean(h.PanelVersion), UpstreamVersion: Clean(h.UpstreamVersion),
		XrayVersion: Clean(h.XrayVersion), Auth: Clean(h.Auth), Local: h.Local, DialTargets: h.DialTargets}
	fmt.Fprintf(w, "%s: %s\n", h.Tool, h.PanelURL)
	panel := i18n.T("version.desc", h.PanelKind, h.PanelVersion)
	if h.UpstreamVersion != "" {
		panel = i18n.T("version.desc_based", h.PanelKind, h.PanelVersion, h.UpstreamVersion)
	}
	var auth any = h.Auth
	switch h.Auth {
	case "API token":
		auth = i18n.T("report.auth_token")
	case "password":
		auth = i18n.T("report.auth_password")
	}
	fmt.Fprint(w, i18n.T("report.panel", panel, orDash(h.XrayVersion), auth).In(l))
	if h.Local {
		fmt.Fprint(w, i18n.T("report.local").In(l))
	} else if h.DialTargets {
		fmt.Fprint(w, i18n.T("report.dial").In(l))
	}
	fmt.Fprintln(w)

	sorted := append([]checks.Finding(nil), fs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Severity > sorted[j].Severity })
	counts := map[checks.Severity]int{}
	cur := checks.Severity(-1)
	for _, f := range sorted {
		counts[f.Severity]++
		if f.Severity == checks.OK && !showOK {
			continue
		}
		if f.Severity != cur {
			cur = f.Severity
			fmt.Fprintf(w, "\n== %s ==\n", cur)
		}
		subject, message, fix := f.In(l)
		line := "[" + Clean(f.Check) + "] "
		if subject != "" {
			line += Clean(subject) + ": "
		}
		fmt.Fprintln(w, "- "+line+Clean(message))
		if fix != "" {
			fmt.Fprintln(w, i18n.T("report.fix", Clean(fix)).In(l))
		}
	}
	var parts []string
	for _, s := range []struct {
		sev  checks.Severity
		name i18n.Text
	}{
		{checks.Critical, i18n.T("report.critical")},
		{checks.Warn, i18n.T("report.warn")},
		{checks.Info, i18n.T("report.info")},
		{checks.OK, i18n.T("report.ok")},
	} {
		parts = append(parts, i18n.T("report.count", counts[s.sev], s.name).In(l))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, i18n.T("report.summary", strings.Join(parts, ", ")).In(l))
	if !showOK && counts[checks.OK] > 0 {
		fmt.Fprintln(w, i18n.T("report.ok_hidden").In(l))
	}
}

// ExitCode maps the worst severity to 0 ok / 1 warnings / 2 critical.
func ExitCode(fs []checks.Finding) int {
	switch checks.Worst(fs) {
	case checks.Critical:
		return 2
	case checks.Warn:
		return 1
	}
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
