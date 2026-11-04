package doctor

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Dv2Corn/xui-doctor/internal/api"
	"github.com/Dv2Corn/xui-doctor/internal/i18n"
	"github.com/Dv2Corn/xui-doctor/internal/report"
)

// TestRussianReport runs every check against the recorded 3x-ui panel and
// renders the report in Russian; JSON from the same findings stays English.
func TestRussianReport(t *testing.T) {
	_, srv := newFakePanel(t, "3x-ui-3.11.0", false)
	s := collect(t, srv, api.Credentials{Username: "tester", Password: "fake-pass"})
	fs := findings(s)
	h := report.Header{Tool: "xui-doctor test", PanelURL: s.PanelURL, PanelKind: s.Kind, PanelVersion: s.Status.PanelVersion,
		XrayVersion: s.Status.Xray.Version, Auth: s.AuthMethod, Lang: i18n.RU}
	var b bytes.Buffer
	report.Text(&b, h, fs, true)
	out := b.String()
	t.Logf("Russian report:\n%s", out)
	for _, want := range []string{
		"панель: 3x-ui 3.11.0, Xray 26.10.21, авторизация: пароль",
		`- [xray] вход #1 "reality-ios" (vless, порт 24443): Xray 26.10.21 (>= 26.9.8) не пускает по REALITY ClientHello без ключа X25519MLKEM768; ссылки здесь с fp=ios, а в нём такого ключа нет, и клиенты по ним не подключатся`,
		"  что делать: Поставьте отпечаток uTLS chrome, firefox или safari и пусть клиенты обновят подписку, или закрепите Xray 26.6.27",
		"- [security] вход в панель: двухфакторная аутентификация выключена",
		"  что делать: Включите её: Settings -> Authentication -> Two-factor authentication.",
		"- [clients] клиенты: у 1 клиента задан лимит IP (limitIp), но fail2ban на сервере панели не работает (enabled=no, installed=no, usable=no), так что лимит не соблюдается",
		"- [tls] входы TLS: 1 файл сертификата не проверен; чтобы их прочитать, запустите с --local на сервере панели",
		"- [version] панель: 3x-ui 3.11.0; последний выпуск не проверялся (--offline)",
		"итого: CRITICAL ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Russian report lacks %q", want)
		}
	}
	for _, english := range []string{"fix:", "summary:", "two-factor", "refuses", "inbound #", "not checked", "auth:"} {
		if strings.Contains(out, english) {
			t.Errorf("Russian report still contains %q", english)
		}
	}

	var j bytes.Buffer
	if err := report.JSON(&j, h, fs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(j.String(), `"message": "two-factor authentication is off"`) || !strings.Contains(j.String(), `"id": "security.no_2fa"`) ||
		strings.Contains(j.String(), "двухфакторная") {
		t.Errorf("JSON must stay English with stable ids:\n%s", j.String())
	}
}
