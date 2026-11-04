// Package report renders findings as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Dv2Corn/xui-doctor/internal/checks"
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
}

// JSON writes {"header":..., "worst":..., "findings":[...]}.
func JSON(w io.Writer, h Header, fs []checks.Finding) error {
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

// Text writes findings grouped by severity, worst first. Every string is
// passed through Clean before it reaches the terminal.
func Text(w io.Writer, h Header, fs []checks.Finding, showOK bool) {
	h = Header{Tool: Clean(h.Tool), PanelURL: Clean(h.PanelURL), PanelKind: Clean(h.PanelKind),
		PanelVersion: Clean(h.PanelVersion), UpstreamVersion: Clean(h.UpstreamVersion),
		XrayVersion: Clean(h.XrayVersion), Auth: Clean(h.Auth), Local: h.Local, DialTargets: h.DialTargets}
	fmt.Fprintf(w, "%s: %s\n", h.Tool, h.PanelURL)
	panel := h.PanelKind + " " + h.PanelVersion
	if h.UpstreamVersion != "" {
		panel += " (based on 3x-ui " + h.UpstreamVersion + ")"
	}
	fmt.Fprintf(w, "panel: %s, Xray %s, auth: %s", panel, orDash(h.XrayVersion), h.Auth)
	if h.Local {
		fmt.Fprint(w, ", local checks on")
	} else if h.DialTargets {
		fmt.Fprint(w, ", dialing REALITY targets from this machine")
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
		line := "[" + Clean(f.Check) + "] "
		if f.Subject != "" {
			line += Clean(f.Subject) + ": "
		}
		fmt.Fprintln(w, "- "+line+Clean(f.Message))
		if f.Fix != "" {
			fmt.Fprintln(w, "  fix: "+Clean(f.Fix))
		}
	}
	var parts []string
	for _, s := range []checks.Severity{checks.Critical, checks.Warn, checks.Info, checks.OK} {
		parts = append(parts, fmt.Sprintf("%d %s", counts[s], strings.ToLower(s.String())))
	}
	fmt.Fprintf(w, "\nsummary: %s\n", strings.Join(parts, ", "))
	if !showOK && counts[checks.OK] > 0 {
		fmt.Fprintln(w, "(OK lines hidden; use --verbose to show them)")
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
