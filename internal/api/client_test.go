package api

import (
	"strings"
	"testing"
	"time"
)

func TestNewURL(t *testing.T) {
	_, err := New("https://admin:s3cret@panel.example:2053/x/", Credentials{}, false, time.Second)
	if err == nil || strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), "XUI_USERNAME") {
		t.Fatalf("userinfo must be refused without echoing the password: %v", err)
	}
	for _, bad := range []string{"", "panel.example:2053", "ftp://panel.example/", "https://"} {
		if _, err := New(bad, Credentials{}, false, time.Second); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	c, err := New(" https://panel.example:2053/x/?a=b#frag ", Credentials{}, false, time.Second)
	if err != nil || c.Base() != "https://panel.example:2053/x" {
		t.Fatalf("normalize: %v %q", err, c.Base())
	}
}
