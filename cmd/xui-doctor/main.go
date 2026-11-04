// Command xui-doctor is a read-only health and configuration checker for
// 3x-ui and still-ui panels.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Dv2Corn/xui-doctor/internal/api"
	"github.com/Dv2Corn/xui-doctor/internal/checks"
	"github.com/Dv2Corn/xui-doctor/internal/doctor"
	"github.com/Dv2Corn/xui-doctor/internal/local"
	"github.com/Dv2Corn/xui-doctor/internal/report"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `xui-doctor - read-only health and config checker for 3x-ui / still-ui panels

Usage:
  xui-doctor check --url https://HOST:PORT/BASEPATH/ [flags]
  xui-doctor version

Credentials come from the environment, never from flags:
  XUI_API_TOKEN               API token (Settings -> API Tokens; admin scope reads everything,
                              a monitor-scope token only allows the Xray/version checks)
  XUI_USERNAME, XUI_PASSWORD  panel login, used when no token is set
  XUI_2FA_CODE                current two-factor code, if 2FA is on

The tool sends GET requests plus POST /login, /logout and /panel/api/setting/all
(a read). It never changes the panel.

Exit code: 0 no warnings, 1 warnings, 2 critical findings, 3 the check could not run.

Flags for check:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		fs, _ := checkFlags(stdout)
		fs.PrintDefaults()
		return 0
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, "xui-doctor", version)
		return 0
	case "check":
	default:
		fmt.Fprintf(stderr, "unknown command %q; try: xui-doctor check --url ...\n", args[0])
		return 3
	}

	fs, opt := checkFlags(stderr)
	if err := fs.Parse(args[1:]); err != nil {
		return 3
	}
	if opt.url == "" {
		fmt.Fprintln(stderr, "missing --url (e.g. --url https://203.0.113.5:2053/abcdef/)")
		return 3
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	snap, err := doctor.Collect(ctx, doctor.Options{
		URL: opt.url,
		Creds: api.Credentials{
			Token:         strings.TrimSpace(os.Getenv("XUI_API_TOKEN")),
			Username:      os.Getenv("XUI_USERNAME"),
			Password:      os.Getenv("XUI_PASSWORD"),
			TwoFactorCode: strings.TrimSpace(os.Getenv("XUI_2FA_CODE")),
		},
		Insecure: opt.insecure,
		Timeout:  opt.timeout,
		Offline:  opt.offline,
		Local:    opt.local,
		Dial:     opt.dial,
		Probe:    &local.Probe{AllowNonPublic: opt.local},
	})
	if err != nil {
		var fe doctor.ErrFatal
		if errors.As(err, &fe) {
			err = fe.Err
		}
		fmt.Fprintln(stderr, "xui-doctor:", report.Clean(err.Error()))
		if strings.Contains(err.Error(), "x509:") && !opt.insecure {
			fmt.Fprintln(stderr, "hint: for a self-signed panel certificate add --insecure")
		}
		return 3
	}
	findings := checks.Run(snap)
	h := report.Header{
		Tool:            "xui-doctor " + version,
		PanelURL:        snap.PanelURL,
		PanelKind:       snap.Kind,
		PanelVersion:    snap.Status.PanelVersion,
		UpstreamVersion: snap.Status.UpstreamVersion,
		XrayVersion:     snap.Status.Xray.Version,
		Auth:            snap.AuthMethod,
		Local:           snap.Local,
		DialTargets:     snap.Dial,
	}
	if opt.json {
		if err := report.JSON(stdout, h, findings); err != nil {
			fmt.Fprintln(stderr, "xui-doctor:", err)
			return 3
		}
	} else {
		report.Text(stdout, h, findings, opt.verbose)
	}
	return report.ExitCode(findings)
}

type flagValues struct {
	url                                           string
	insecure, json, local, dial, offline, verbose bool
	timeout                                       time.Duration
}

func checkFlags(out io.Writer) (*flag.FlagSet, *flagValues) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(out)
	opt := &flagValues{}
	fs.StringVar(&opt.url, "url", os.Getenv("XUI_URL"), "panel URL including its base path (or XUI_URL)")
	fs.BoolVar(&opt.insecure, "insecure", false, "accept a self-signed or mismatched panel certificate")
	fs.BoolVar(&opt.json, "json", false, "print JSON instead of text")
	fs.BoolVar(&opt.local, "local", false, "running on the panel host: also read certificate files and listening sockets, and dial REALITY targets")
	fs.BoolVar(&opt.dial, "dial-targets", false, "dial REALITY targets from this machine; non-public addresses only with --local (implied by --local)")
	fs.BoolVar(&opt.offline, "offline", false, "do not ask GitHub for the latest panel release")
	fs.BoolVar(&opt.verbose, "verbose", false, "also print OK lines")
	fs.DurationVar(&opt.timeout, "timeout", 20*time.Second, "timeout per panel request")
	return fs, opt
}
