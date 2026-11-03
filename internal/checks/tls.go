package checks

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

const certWarnBefore = 7 * 24 * time.Hour

// checkTLS looks at certificates of TLS inbounds (inline PEM always, files
// with --local) and at the certificate the panel itself presented.
func checkTLS(s *Snapshot) []Finding {
	var out []Finding
	if s.PanelCert != nil {
		out = append(out, certFinding(s.Now, "panel HTTPS certificate", s.PanelCert,
			"Renew the panel certificate (Settings -> panel certificate, or your ACME client)")...)
	}
	if s.Local && s.Settings != nil && s.Probe != nil {
		for _, p := range []struct{ what, path string }{
			{"panel certificate file", s.Settings.WebCertFile},
			{"subscription certificate file", s.Settings.SubCertFile},
		} {
			if strings.TrimSpace(p.path) == "" || (p.what == "subscription certificate file" && !s.Settings.SubEnable) {
				continue
			}
			out = append(out, fileCert(s, p.what+" "+p.path, p.path)...)
		}
	}
	if f, ok := s.skipped("inbounds"); ok {
		return append(out, f)
	}
	files := 0
	for i := range s.Inbounds {
		ib := &s.Inbounds[i]
		if !ib.Enable || ib.Stream.Security != "tls" || ib.Stream.TLSSettings == nil {
			continue
		}
		if len(ib.Stream.TLSSettings.Certificates) == 0 {
			out = append(out, Finding{Severity: Critical, Subject: ib.label(), Message: "TLS is on but no certificate is configured",
				Fix: "Add a certificate (file paths or content) to the inbound's TLS settings."})
			continue
		}
		for _, c := range ib.Stream.TLSSettings.Certificates {
			switch {
			case c.InlinePEM() != "":
				cert, err := parsePEM([]byte(c.InlinePEM()))
				if err != nil {
					out = append(out, Finding{Severity: Critical, Subject: ib.label(), Message: "inline certificate does not parse: " + err.Error()})
					continue
				}
				out = append(out, certFinding(s.Now, ib.label()+" inline certificate", cert, "Replace the inline certificate with a renewed one")...)
			case c.CertificateFile != "":
				if !ib.local() {
					continue // the file lives on the node
				}
				if !s.Local || s.Probe == nil {
					files++
					continue
				}
				out = append(out, fileCert(s, ib.label()+" "+c.CertificateFile, c.CertificateFile)...)
			}
		}
	}
	if files > 0 {
		out = append(out, Finding{Severity: Info, Subject: "TLS inbounds",
			Message: fmt.Sprintf("%d certificate %s not checked; run with --local on the panel host to read them", files, plural(files, "file", "files"))})
	}
	return out
}

func fileCert(s *Snapshot, subject, path string) []Finding {
	cert, err := s.Probe.ReadCertFile(path)
	if err != nil {
		return []Finding{{Severity: Critical, Subject: subject, Message: "cannot read certificate: " + err.Error(),
			Fix: "Check the path in the panel and the file permissions."}}
	}
	return certFinding(s.Now, subject, cert, "Renew the certificate and restart Xray (or wait for the panel to reload it)")
}

func certFinding(now time.Time, subject string, c *x509.Certificate, fix string) []Finding {
	left := c.NotAfter.Sub(now)
	exp := c.NotAfter.UTC().Format("2006-01-02 15:04 UTC")
	switch {
	case left <= 0:
		return []Finding{{Severity: Critical, Subject: subject, Message: "certificate expired on " + exp, Fix: fix + "."}}
	case left < certWarnBefore:
		return []Finding{{Severity: Warn, Subject: subject,
			Message: fmt.Sprintf("certificate expires in %s (%s)", roundDuration(left), exp),
			Fix:     fix + "; short-lived (e.g. IP) certificates must renew automatically."}}
	case now.Before(c.NotBefore):
		return []Finding{{Severity: Warn, Subject: subject, Message: "certificate is not valid yet (from " + c.NotBefore.UTC().Format(time.RFC3339) + "); check the server clock"}}
	}
	return []Finding{{Severity: OK, Subject: subject, Message: "valid until " + exp}}
}

func parsePEM(data []byte) (*x509.Certificate, error) {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil, fmt.Errorf("no PEM certificate found")
		}
		if b.Type == "CERTIFICATE" {
			return x509.ParseCertificate(b.Bytes)
		}
	}
}

// ParsePEM is exported for package local.
func ParsePEM(data []byte) (*x509.Certificate, error) { return parsePEM(data) }

func roundDuration(d time.Duration) string {
	if d >= 48*time.Hour {
		days := int(d.Hours() / 24)
		hours := int(d.Hours()) - days*24
		return fmt.Sprintf("%d days %d hours", days, hours)
	}
	if d >= time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d minutes", int(d.Minutes()))
}
