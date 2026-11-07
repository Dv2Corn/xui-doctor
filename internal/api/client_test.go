package api

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewURL(t *testing.T) {
	_, err := New("https://admin:s3cret@panel.example:2053/x/", Credentials{}, false, time.Second)
	if err == nil || strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "/x/") || !strings.Contains(err.Error(), "XUI_USERNAME") {
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

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://panel.example:2053/s3cret/":  "https://panel.example:2053/***/",
		"https://panel.example:2053/s3cret":   "https://panel.example:2053/***/",
		"http://u:p@127.0.0.1:2053/a/b?q=1#f": "http://127.0.0.1:2053/***/",
		"https://panel.example:2053/":         "https://panel.example:2053/",
		"https://panel.example":               "https://panel.example/",
		"/s3cret/login":                       "/***/",
		"":                                    "",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetworkErrorHidesBasePath(t *testing.T) {
	c, err := New("http://127.0.0.1:1/s3cretPath/", Credentials{Token: "t"}, false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Status(context.Background())
	if err == nil || strings.Contains(err.Error(), "s3cretPath") {
		t.Fatalf("error must not carry the base path: %v", err)
	}
}
