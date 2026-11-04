package checks

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"github.com/Dv2Corn/xui-doctor/internal/i18n"
)

const certWarnBefore = 7 * 24 * time.Hour

// checkTLS looks at certificates of TLS inbounds (inline PEM always, files
// with --local) and at the certificate the panel itself presented.
func checkTLS(s *Snapshot) []Finding {
	var out []Finding
	if s.PanelCert != nil {
		out = append(out, certFinding(s.Now, i18n.T("subj.panel_cert"), s.PanelCert, i18n.T("tls.renew_panel"))...)
	}
	if s.Local && s.Settings != nil && s.Probe != nil {
		for _, p := range []struct {
			what i18n.Text
			path string
			on   bool
		}{
			{i18n.T("tls.panel_file"), s.Settings.WebCertFile, true},
			{i18n.T("tls.sub_file"), s.Settings.SubCertFile, s.Settings.SubEnable},
		} {
			if strings.TrimSpace(p.path) == "" || !p.on {
				continue
			}
			out = append(out, fileCert(s, i18n.T("tls.subj_file", p.what, p.path), p.path)...)
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
			out = append(out, newFinding(Critical, ib.label(), i18n.T("tls.no_cert"), i18n.T("tls.no_cert.fix")))
			continue
		}
		for _, c := range ib.Stream.TLSSettings.Certificates {
			switch {
			case c.InlinePEM() != "":
				cert, err := parsePEM([]byte(c.InlinePEM()))
				if err != nil {
					out = append(out, newFinding(Critical, ib.label(), i18n.T("tls.inline_bad", err), i18n.Text{}))
					continue
				}
				out = append(out, certFinding(s.Now, i18n.T("tls.subj_inline", ib.label()), cert, i18n.T("tls.renew_inline"))...)
			case c.CertificateFile != "":
				if !ib.local() {
					continue // the file lives on the node
				}
				if !s.Local || s.Probe == nil {
					files++
					continue
				}
				out = append(out, fileCert(s, i18n.T("tls.subj_file", ib.label(), c.CertificateFile), c.CertificateFile)...)
			}
		}
	}
	if files > 0 {
		out = append(out, newFinding(Info, i18n.T("subj.tls_inbounds"),
			i18n.T("tls.files_unchecked", files, i18n.Plural("n.cert_file", files)), i18n.Text{}))
	}
	return out
}

func fileCert(s *Snapshot, subject i18n.Text, path string) []Finding {
	cert, err := s.Probe.ReadCertFile(path)
	if err != nil {
		return []Finding{newFinding(Critical, subject, i18n.T("tls.read_failed", err), i18n.T("tls.read_failed.fix"))}
	}
	return certFinding(s.Now, subject, cert, i18n.T("tls.renew_file"))
}

func certFinding(now time.Time, subject i18n.Text, c *x509.Certificate, fix i18n.Text) []Finding {
	left := c.NotAfter.Sub(now)
	exp := c.NotAfter.UTC().Format("2006-01-02 15:04 UTC")
	switch {
	case left <= 0:
		return []Finding{newFinding(Critical, subject, i18n.T("tls.expired", exp), i18n.T("tls.fix_now", fix))}
	case left < certWarnBefore:
		return []Finding{newFinding(Warn, subject, i18n.T("tls.expires_soon", roundDuration(left), exp), i18n.T("tls.fix_soon", fix))}
	case now.Before(c.NotBefore):
		return []Finding{newFinding(Warn, subject, i18n.T("tls.not_yet_valid", c.NotBefore.UTC().Format(time.RFC3339)), i18n.Text{})}
	}
	return []Finding{newFinding(OK, subject, i18n.T("tls.valid_until", exp), i18n.Text{})}
}

func parsePEM(data []byte) (*x509.Certificate, error) {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil, i18n.Errorf("tls.no_pem")
		}
		if b.Type == "CERTIFICATE" {
			return x509.ParseCertificate(b.Bytes)
		}
	}
}

// ParsePEM is exported for package local.
func ParsePEM(data []byte) (*x509.Certificate, error) { return parsePEM(data) }

func roundDuration(d time.Duration) i18n.Text {
	if d >= 48*time.Hour {
		days := int(d.Hours() / 24)
		hours := int(d.Hours()) - days*24
		return i18n.T("dur.days_hours", days, i18n.Plural("n.day", days), hours, i18n.Plural("n.hour", hours))
	}
	if d >= time.Hour {
		h := int(d.Hours())
		return i18n.T("dur.count", h, i18n.Plural("n.hour", h))
	}
	m := int(d.Minutes())
	return i18n.T("dur.count", m, i18n.Plural("n.minute", m))
}
