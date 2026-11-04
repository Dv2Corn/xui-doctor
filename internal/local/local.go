// Package local implements the optional host-side reads (certificate files,
// listening sockets) and TLS dials used by --local and --dial-targets.
// Nothing here writes anywhere.
package local

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Dv2Corn/xui-doctor/internal/checks"
)

// Probe is the real implementation of checks.Probe.
type Probe struct {
	Timeout time.Duration
	// ProcNet is the directory holding tcp, tcp6, udp, udp6 (default /proc/net).
	ProcNet string
	// AllowNonPublic lets DialTLS connect to loopback/private/special
	// addresses (--local). Otherwise the dialer refuses them on the address it
	// actually connects to.
	AllowNonPublic bool
}

// guard is a net.Dialer Control hook that re-checks the connected address.
func (p *Probe) guard(_, address string, _ syscall.RawConn) error {
	if p.AllowNonPublic {
		return nil
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !checks.PublicAddr(ap.Addr()) {
		return fmt.Errorf("refusing to dial non-public address %s without --local", address)
	}
	return nil
}

// ReadCertFile parses the first certificate of a PEM file (at most 1 MiB is read).
func (p *Probe) ReadCertFile(path string) (*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, err
	}
	return checks.ParsePEM(data)
}

// Listening reads /proc/net/{tcp,tcp6,udp,udp6} (Linux only).
func (p *Probe) Listening() (map[string]bool, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("only supported on Linux")
	}
	dir := p.ProcNet
	if dir == "" {
		dir = "/proc/net"
	}
	out := map[string]bool{}
	for _, f := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		if err := parseProcNet(dir+"/"+f.file, f.proto, out); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return out, nil
}

// parseProcNet adds "proto/port" for LISTEN TCP sockets (state 0A) and for
// every bound UDP socket.
func parseProcNet(path, proto string, out map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if proto == "tcp" && fields[3] != "0A" {
			continue
		}
		i := strings.LastIndexByte(fields[1], ':')
		if i < 0 {
			continue
		}
		port, err := strconv.ParseUint(fields[1][i+1:], 16, 16)
		if err != nil || port == 0 {
			continue
		}
		out[fmt.Sprintf("%s/%d", proto, port)] = true
	}
	return sc.Err()
}

// LookupIP resolves host with the system resolver.
func (p *Probe) LookupIP(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout())
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

func (p *Probe) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return 5 * time.Second
}

// DialTLS performs a TLS handshake like a browser would (SNI, h2 + http/1.1)
// and verifies the certificate for sni against the system roots.
func (p *Probe) DialTLS(addr, sni string) (*checks.TLSResult, error) {
	timeout := p.timeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout, Control: p.guard},
		Config: &tls.Config{
			ServerName:         sni,
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: true, //nolint:gosec // verified below so we can report why
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	cs := conn.(*tls.Conn).ConnectionState()
	res := &checks.TLSResult{Version: cs.Version, ALPN: cs.NegotiatedProtocol}
	if len(cs.PeerCertificates) > 0 {
		res.Leaf = cs.PeerCertificates[0]
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		_, res.VerifyError = res.Leaf.Verify(x509.VerifyOptions{DNSName: sni, Intermediates: inter})
		var ua x509.UnknownAuthorityError
		res.UnknownRoot = errors.As(res.VerifyError, &ua)
	} else {
		res.VerifyError = errors.New("no certificate presented")
	}
	return res, nil
}
