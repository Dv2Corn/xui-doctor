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
		var out, errb bytes.Buffer
		if got := run(c.args, &out, &errb); got != c.code {
			t.Errorf("%v: exit %d want %d (%s%s)", c.args, got, c.code, out.String(), errb.String())
		}
		if !strings.Contains(out.String()+errb.String(), c.out) {
			t.Errorf("%v: output lacks %q: %s%s", c.args, c.out, out.String(), errb.String())
		}
	}
}
