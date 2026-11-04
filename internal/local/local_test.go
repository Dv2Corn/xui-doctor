package local

import (
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseProcNet(t *testing.T) {
	dir := t.TempDir()
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:2F0D 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0100007F:9C40 0100007F:01BB 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
`
	udp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  10: 00000000:A5E0 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4 2 0000000000000000 0
`
	if err := os.WriteFile(filepath.Join(dir, "tcp"), []byte(tcp), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "udp"), []byte(udp), 0o600); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, f := range []struct{ file, proto string }{{"tcp", "tcp"}, {"udp", "udp"}} {
		if err := parseProcNet(filepath.Join(dir, f.file), f.proto, out); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"tcp/443", "tcp/12045", "udp/42464"} {
		if !out[want] {
			t.Errorf("missing %s in %v", want, out)
		}
	}
	if out["tcp/40000"] {
		t.Error("an established socket is not a listener")
	}
}

func TestDialTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	p := &Probe{Timeout: 3 * time.Second}
	res, err := p.DialTLS(strings.TrimPrefix(srv.URL, "https://"), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != tls.VersionTLS13 || res.ALPN != "h2" {
		t.Fatalf("version %x alpn %q", res.Version, res.ALPN)
	}
	if res.VerifyError == nil || !res.UnknownRoot {
		t.Fatalf("the httptest certificate must fail as an unknown root: %v", res.VerifyError)
	}
	if res, err = p.DialTLS(strings.TrimPrefix(srv.URL, "https://"), "other.test"); err != nil || res.VerifyError == nil || res.UnknownRoot {
		t.Fatalf("a name mismatch must not count as an unknown root: %v %+v", err, res)
	}
}

func TestReadCertFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	p := &Probe{}
	good := filepath.Join(t.TempDir(), "good.pem")
	_ = os.WriteFile(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	if c, err := p.ReadCertFile(good); err != nil || !c.NotAfter.Equal(srv.Certificate().NotAfter) {
		t.Fatalf("read good cert: %v", err)
	}
	if _, err := p.ReadCertFile(filepath.Join(t.TempDir(), "none.pem")); err == nil {
		t.Fatal("missing file must fail")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a pem"), 0o600)
	if _, err := p.ReadCertFile(bad); err == nil {
		t.Fatal("garbage must fail")
	}
}

func TestLookupIP(t *testing.T) {
	ips, err := (&Probe{Timeout: 2 * time.Second}).LookupIP("localhost")
	if err != nil || len(ips) == 0 || !ips[0].IsLoopback() {
		t.Fatalf("localhost: %v %v", ips, err)
	}
}
