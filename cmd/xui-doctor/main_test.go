package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunArgs(t *testing.T) {
	for _, c := range []struct {
		args []string
		code int
		out  string
	}{
		{nil, 0, "Usage:"},
		{[]string{"help"}, 0, "-dial-targets"},
		{[]string{"version"}, 0, "xui-doctor dev"},
		{[]string{"bogus"}, 3, "unknown command"},
		{[]string{"check", "--url", ""}, 3, "missing --url"},
		{[]string{"check", "--no-such-flag"}, 3, "flag provided but not defined"},
		{[]string{"check", "--url", "ftp://x"}, 3, "panel URL must look like"},
	} {
		t.Setenv("XUI_URL", "")
		t.Setenv("LC_ALL", "C")
		var out, errb bytes.Buffer
		if got := run(c.args, &out, &errb); got != c.code {
			t.Errorf("%v: exit %d want %d (%s%s)", c.args, got, c.code, out.String(), errb.String())
		}
		if !strings.Contains(out.String()+errb.String(), c.out) {
			t.Errorf("%v: output lacks %q: %s%s", c.args, c.out, out.String(), errb.String())
		}
	}
}

func TestRunRussian(t *testing.T) {
	t.Setenv("XUI_URL", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "ru_RU.UTF-8")
	for _, c := range []struct {
		args []string
		code int
		out  string
	}{
		{nil, 0, "Запуск:"},
		{[]string{"help"}, 0, "проверить цели REALITY с этой машины"},
		{[]string{"help", "--lang", "en"}, 0, "dial REALITY targets from this machine"},
		{[]string{"bogus"}, 3, "неизвестная команда"},
		{[]string{"check", "--url", ""}, 3, "не задан --url"},
		{[]string{"check", "--lang=en", "--url", ""}, 3, "missing --url"},
		{[]string{"check", "--url", "ftp://x"}, 3, "адрес панели должен выглядеть так"},
		{[]string{"check", "-lang", "de", "--url", "ftp://x"}, 3, `invalid value "de" for flag -lang`},
		{[]string{"check", "-h"}, 0, "Ключи для check:"},
	} {
		var out, errb bytes.Buffer
		if got := run(c.args, &out, &errb); got != c.code {
			t.Errorf("%v: exit %d want %d (%s%s)", c.args, got, c.code, out.String(), errb.String())
		}
		if !strings.Contains(out.String()+errb.String(), c.out) {
			t.Errorf("%v: output lacks %q: %s%s", c.args, c.out, out.String(), errb.String())
		}
	}
}

func TestLangArg(t *testing.T) {
	for args, want := range map[string]string{
		"check --lang ru":           "ru",
		"check -lang=en --url x":    "en",
		"check --url x":             "",
		"check --lang":              "",
		"check -- --lang ru":        "",
		"check --lang en --lang=ru": "ru",
		"check --language ru --url": "",
	} {
		if got := langArg(strings.Fields(args)); got != want {
			t.Errorf("langArg(%q) = %q, want %q", args, got, want)
		}
	}
}
