package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Dv2Corn/xui-doctor/internal/checks"
)

var sample = []checks.Finding{
	{Check: "version", Severity: checks.OK, Message: "fine"},
	{Check: "security", Severity: checks.Warn, Subject: "login", Message: "two-factor authentication is off", Fix: "enable it"},
	{Check: "xray", Severity: checks.Critical, Subject: "inbound #1", Message: "fp=ios", Fix: "use chrome"},
	{Check: "tls", Severity: checks.Info, Message: "files not checked"},
}

func TestText(t *testing.T) {
	var b bytes.Buffer
	Text(&b, Header{Tool: "xui-doctor test", PanelURL: "https://p/x", PanelKind: "still-ui", PanelVersion: "1.3.0", UpstreamVersion: "3.11.0", XrayVersion: "26.10.31", Auth: "API token"}, sample, false)
	out := b.String()
	ci, wi, ii := strings.Index(out, "== CRITICAL =="), strings.Index(out, "== WARN =="), strings.Index(out, "== INFO ==")
	if ci < 0 || wi < ci || ii < wi {
		t.Fatalf("groups out of order:\n%s", out)
	}
	if strings.Contains(out, "== OK ==") || !strings.Contains(out, "OK lines hidden") {
		t.Fatalf("OK lines should be hidden by default:\n%s", out)
	}
	if !strings.Contains(out, "still-ui 1.3.0 (based on 3x-ui 3.11.0)") || !strings.Contains(out, "  fix: use chrome") {
		t.Fatalf("header or fix missing:\n%s", out)
	}
	if !strings.Contains(out, "summary: 1 critical, 1 warn, 1 info, 1 ok") {
		t.Fatalf("summary:\n%s", out)
	}
	if !strings.HasPrefix(out, "xui-doctor test: https://p/***/\n") {
		t.Fatalf("the base path must be hidden:\n%s", out)
	}
}

func TestJSONAndExit(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, Header{Tool: "t", PanelURL: "https://panel.example:2053/s3cretPath"}, sample); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "s3cretPath") || !strings.Contains(b.String(), `"panelUrl": "https://panel.example:2053/***/"`) {
		t.Fatalf("the base path must be hidden:\n%s", b.String())
	}
	var doc struct {
		Worst    string `json:"worst"`
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Worst != "CRITICAL" || len(doc.Findings) != 4 || doc.Findings[1].Severity != "WARN" {
		t.Fatalf("%+v", doc)
	}
	if ExitCode(sample) != 2 || ExitCode(sample[:2]) != 1 || ExitCode(sample[:1]) != 0 {
		t.Fatal("exit codes")
	}
}

func TestTextStripsControlCharacters(t *testing.T) {
	evil := []checks.Finding{{Check: "clients", Severity: checks.Warn,
		Subject: "inbound #1 \"x\x1b]0;pwned\x07\"", Message: "client \u202eevil\u202c and \x9b31m \u009b31m \u2066x\u2069 and\x7f tab\tok", Fix: "fix\x1b[2J"}}
	var b bytes.Buffer
	Text(&b, Header{Tool: "t", PanelURL: "https://p/\x1b[31m", PanelKind: "3x-ui"}, evil, false)
	out := b.String()
	for _, bad := range []string{"\x1b", "\x07", "\u202e", "\u202c", "\x9b", "\u009b", "\u2066", "\u2069", "\x7f"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q:\n%q", bad, out)
		}
	}
	if !strings.Contains(out, "tab\tok") || !strings.Contains(out, "]0;pwned") {
		t.Errorf("printable text and tabs must stay: %q", out)
	}
}
