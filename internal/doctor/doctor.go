// Package doctor reads a panel into a checks.Snapshot.
package doctor

import (
	"context"
	"time"

	"github.com/Dv2Corn/xui-doctor/internal/api"
	"github.com/Dv2Corn/xui-doctor/internal/checks"
)

// Options controls collection.
type Options struct {
	URL      string
	Creds    api.Credentials
	Insecure bool
	Timeout  time.Duration
	Offline  bool
	Local    bool
	Dial     bool
	Probe    checks.Probe
}

// ErrFatal wraps errors that stop the run (no connection, login refused, no status).
type ErrFatal struct{ Err error }

func (e ErrFatal) Error() string { return e.Err.Error() }
func (e ErrFatal) Unwrap() error { return e.Err }

// Collect logs in, reads everything the checks need and logs out again.
func Collect(ctx context.Context, o Options) (*checks.Snapshot, error) {
	c, err := api.New(o.URL, o.Creds, o.Insecure, o.Timeout)
	if err != nil {
		return nil, ErrFatal{err}
	}
	if err := c.Login(ctx); err != nil {
		return nil, ErrFatal{err}
	}
	defer func() {
		lctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Logout(lctx)
	}()

	s := &checks.Snapshot{
		Now:      time.Now(),
		PanelURL: c.Base(),
		Errors:   map[string]error{},
		Offline:  o.Offline,
		Local:    o.Local,
		Dial:     o.Dial || o.Local,
	}
	if s.Local || s.Dial {
		s.Probe = o.Probe
	}
	s.AuthMethod = "password"
	if c.UsesToken() {
		s.AuthMethod = "API token"
	}
	s.DefaultCredentials = !c.UsesToken() && o.Creds.Username == "admin" && o.Creds.Password == "admin"

	st, err := c.Status(ctx)
	if err != nil {
		return nil, ErrFatal{err}
	}
	s.Status = st
	s.Kind = checks.Kind3XUI
	if st.UpstreamVersion != "" {
		s.Kind = checks.KindStillUI
	}

	if in, err := c.Inbounds(ctx); err != nil {
		s.Errors["inbounds"] = err
	} else {
		s.Inbounds = checks.DecodeInbounds(in)
	}
	if h, err := c.Hosts(ctx); err != nil {
		s.Errors["hosts"] = err
	} else {
		s.Hosts = h
	}
	if set, err := c.Settings(ctx); err != nil {
		s.Errors["settings"] = err
	} else {
		s.Settings = set
	}
	if f, err := c.Fail2ban(ctx); err != nil {
		s.Errors["fail2ban"] = err
	} else {
		s.Fail2ban = f
	}
	s.PanelCert = c.PanelCert

	if !o.Offline {
		tag, err := api.LatestRelease(ctx, checks.ReleaseRepo(s.Kind), 10*time.Second)
		if err != nil {
			s.LatestReleaseErr = short(err)
		}
		s.LatestRelease = tag
	}
	return s, nil
}

func short(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}
