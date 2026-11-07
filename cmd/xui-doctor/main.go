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
	"github.com/Dv2Corn/xui-doctor/internal/i18n"
	"github.com/Dv2Corn/xui-doctor/internal/local"
	"github.com/Dv2Corn/xui-doctor/internal/report"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	// The language is needed before the flags are parsed (help text, errors
	// about the command), so --lang is looked up in the raw arguments first.
	lang, err := i18n.Detect(langArg(args), os.Getenv)
	if err != nil {
		lang, _ = i18n.Detect("", os.Getenv)
	}
	say := func(w io.Writer, t i18n.Text) { fmt.Fprintln(w, t.In(lang)) }

	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, i18n.T("cli.usage").In(lang))
		fs, _ := checkFlags(stdout, lang)
		fs.PrintDefaults()
		return 0
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, "xui-doctor", version)
		return 0
	case "check":
	default:
		say(stderr, i18n.T("cli.unknown_command", args[0]))
		return 3
	}

	fs, opt := checkFlags(stderr, lang)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}
	lang = opt.lang.Lang
	if opt.url == "" {
		say(stderr, i18n.T("cli.missing_url"))
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
		fmt.Fprintln(stderr, "xui-doctor:", report.Clean(i18n.ErrorIn(err, lang)))
		if strings.Contains(err.Error(), "x509:") && !opt.insecure {
			say(stderr, i18n.T("cli.hint_insecure"))
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
		Lang:            lang,
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

// langArg returns the value of -lang/--lang in args ("" when absent).
func langArg(args []string) string {
	val := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, v, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "lang" {
			continue
		}
		if !hasValue && i+1 < len(args) {
			i++
			v = args[i]
		}
		val = v
	}
	return val
}

// langFlag is the --lang value; Set accepts en or ru.
type langFlag struct{ i18n.Lang }

func (f *langFlag) String() string { return string(f.Lang) }

func (f *langFlag) Set(s string) error {
	l, err := i18n.Parse(s)
	if err != nil {
		return err
	}
	f.Lang = l
	return nil
}

type flagValues struct {
	url                                           string
	insecure, json, local, dial, offline, verbose bool
	timeout                                       time.Duration
	lang                                          langFlag
}

// checkFlags defines the check flags with help texts in lang; lang is also
// the --lang default.
func checkFlags(out io.Writer, lang i18n.Lang) (*flag.FlagSet, *flagValues) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() {
		fmt.Fprint(out, i18n.T("cli.usage").In(lang))
		fs.PrintDefaults()
	}
	opt := &flagValues{lang: langFlag{lang}}
	fs.StringVar(&opt.url, "url", os.Getenv("XUI_URL"), i18n.T("cli.flag.url").In(lang))
	fs.BoolVar(&opt.insecure, "insecure", false, i18n.T("cli.flag.insecure").In(lang))
	fs.BoolVar(&opt.json, "json", false, i18n.T("cli.flag.json").In(lang))
	fs.BoolVar(&opt.local, "local", false, i18n.T("cli.flag.local").In(lang))
	fs.BoolVar(&opt.dial, "dial-targets", false, i18n.T("cli.flag.dial_targets").In(lang))
	fs.BoolVar(&opt.offline, "offline", false, i18n.T("cli.flag.offline").In(lang))
	fs.BoolVar(&opt.verbose, "verbose", false, i18n.T("cli.flag.verbose").In(lang))
	fs.DurationVar(&opt.timeout, "timeout", 20*time.Second, i18n.T("cli.flag.timeout").In(lang))
	fs.Var(&opt.lang, "lang", i18n.T("cli.flag.lang").In(lang))
	return fs, opt
}
