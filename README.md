**[English](README.md)** | [Русский](README.ru.md) | [فارسی](README.fa.md) | [简体中文](README.zh.md)

# xui-doctor

A small, read-only health and configuration checker for
[3x-ui](https://github.com/MHSanaei/3x-ui) panels and its fork
[still-ui](https://github.com/Dv2Corn/still-ui).

It logs in to the panel API, reads the server status, inbounds, hosts and
settings, and prints what is broken or risky, grouped by severity, with a
one-line fix for each finding. It never changes anything on the panel.

Output from a throwaway test panel (long lines shortened with "..."):

```
$ XUI_API_TOKEN=... xui-doctor check --url http://127.0.0.1:12053/doctor-test/
xui-doctor v0.1.0: http://127.0.0.1:12053/doctor-test
panel: 3x-ui 3.11.0, Xray 26.10.21, auth: API token

== CRITICAL ==
- [xray] inbound #1 "reality-ios" (vless, port 24443): Xray 26.10.21 (>= 26.9.8) refuses REALITY
  ClientHellos without an X25519MLKEM768 key share; share links here use fp=ios, which has none,
  so clients using them cannot connect
  fix: Set the uTLS fingerprint to chrome, firefox or safari and let clients refresh the
  subscription, or pin Xray 26.6.27 in the panel's Xray version switcher ...
- [xray] host "edge-host" -> inbound #1 "reality-ios" (vless, port 24443): ... this host has
  "Mihomo X25519" on, so its Clash subscription turns ML-KEM off and mihomo clients are refused
- [tls] inbound #4 "trojan-tls-inline" (trojan, port 24445) inline certificate: certificate
  expired on 2026-11-01 23:25 UTC
  fix: Replace the inline certificate with a renewed one.

== WARN ==
- [xray] REALITY clients: ... sing-box based clients (sing-box, Hiddify, Karing, NekoBox; tested
  1.12.12 and 1.14.4) cannot connect with any fingerprint; ...
- [clients] clients: 1 client has an IP limit (limitIp) but fail2ban is not usable on the panel
  host (enabled=no, installed=no, usable=no), so the limit is not enforced
- [security] login: two-factor authentication is off
  fix: Enable it in Settings -> Authentication -> Two-factor authentication.

== INFO ==
- [tls] TLS inbounds: 1 certificate file not checked; run with --local on the panel host to read them

summary: 4 critical, 3 warn, 1 info, 3 ok
(OK lines hidden; use --verbose to show them)
```

## Supported panels

| Panel | Tested with | Notes |
|---|---|---|
| 3x-ui (MHSanaei) | v3.11.0 (Docker image `ghcr.io/mhsanaei/3x-ui:v3.11.0`) | v3.x API; older 2.x panels may work partly (untested) |
| still-ui (Dv2Corn) | v1.3.0 (release archive) | detected by the `upstreamVersion` field in the server status |

The tool reports which panel it found. For the version check it compares
3x-ui with the latest release of `MHSanaei/3x-ui` and still-ui with the latest
release of `Dv2Corn/still-ui`.

## Install

```
go install github.com/Dv2Corn/xui-doctor/cmd/xui-doctor@latest
```

or build a static binary (no CGO, standard library only):

```
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o xui-doctor ./cmd/xui-doctor
```

## Usage

```
xui-doctor check --url https://HOST:PORT/BASEPATH/ [--insecure] [--json] [--local]
                 [--dial-targets] [--offline] [--verbose] [--timeout 20s] [--lang en|ru]
```

Credentials are read from the environment only, so they do not end up in the
shell history or the process list:

| Variable | Meaning |
|---|---|
| `XUI_API_TOKEN` | API token (Settings -> Authentication -> API tokens). An *Administrator* token reads everything; a *Monitoring* token only allows the Xray and version checks. |
| `XUI_USERNAME`, `XUI_PASSWORD` | panel login, used when no token is set |
| `XUI_2FA_CODE` | current two-factor code, if 2FA is on |
| `XUI_URL` | default for `--url` |

| Flag | Meaning |
|---|---|
| `--url` | panel address including its URI path (base path); credentials in the URL are refused |
| `--insecure` | accept a self-signed or mismatched panel certificate |
| `--json` | machine-readable output |
| `--local` | the tool runs on the panel host: also read certificate files and listening sockets (`/proc/net`), and dial REALITY targets from there (local and private targets included) |
| `--dial-targets` | dial REALITY targets from wherever the tool runs (reported as such: it may not be the panel host); targets that resolve to loopback, private, link-local, CGNAT, documentation, NAT64/6to4 or other IANA special-purpose addresses are skipped |
| `--offline` | skip the GitHub release lookup |
| `--verbose` | also print OK lines |
| `--lang` | output language, `en` or `ru`; without it a Russian locale (`LC_ALL`, `LC_MESSAGES` or `LANG` starting with `ru`, checked in that order) selects Russian, anything else English |

Text output is in English or Russian. JSON output always keeps English text
and adds a stable message `id` to every finding, so scripts do not depend on
the wording or the locale.

Exit codes: `0` nothing worse than INFO, `1` warnings, `2` critical findings,
`3` the check could not run (wrong URL, login refused, ...).

### What it sends

Only these requests, relative to the panel URL:

- `GET /csrf-token`, `POST /login`, `POST /logout` - its own session (not with a token);
- `GET /panel/api/server/status`, `GET /panel/api/inbounds/list`,
  `GET /panel/api/hosts/list`, `GET /panel/api/server/fail2banStatus`;
- `POST /panel/api/setting/all` - a read; the panel routes it as POST and
  blanks secret values (bot tokens, 2FA secret) in the answer.

With `--local` or `--dial-targets` it also makes TLS handshakes with the
REALITY targets: each name is resolved once and the vetted address is dialed
(5 s timeout, at most 20 handshakes per run; skipped ones are listed).
Without `--local`, non-public target addresses are never dialed; the
dialer checks the address it actually connects to as well.

Plus, unless `--offline`, one unauthenticated call to
`api.github.com/repos/<repo>/releases/latest`. Client UUIDs, passwords and
REALITY private keys are read into memory to be compared with each other and
are never printed.

## Checks

| ID | What it looks at |
|---|---|
| `xray` | Xray state and version against the REALITY changes below; uTLS fingerprints of REALITY inbounds and of subscription hosts; the hosts' "Mihomo X25519" switch |
| `reality` | target, serverNames, privateKey, shortIds exactly as Xray-core validates them; empty public key for links; `show`; with `--local`/`--dial-targets`: TLS 1.3, h2 and a valid certificate for every serverName at the target |
| `tls` | expiry of inline certificates of TLS inbounds and of the certificate the panel presented; with `--local` also certificate files of inbounds, panel and subscription server (expired: CRITICAL, < 7 days: WARN) |
| `ports` | enabled inbounds (and the panel / subscription server) that would bind the same port and transport on the same address, using the panel's own TCP/UDP rules; with `--local` enabled inbounds nobody listens on |
| `clients` | clients past expiry or over quota but still enabled; two clients sharing one UUID/password inside an inbound; IP limits while fail2ban is unusable |
| `security` | admin/admin (only if you ran the tool with it), plain HTTP, URI path `/`, default port 2053 and default subscription paths, 2FA off, Telegram bot token present |
| `version` | panel version against the latest GitHub release |

Inbounds that run on remote nodes are skipped by checks that depend on the
local Xray; run the tool against each node.

### Checks considered and dropped

- *Same e-mail on several inbounds* - since 3x-ui 3.x a client is one record
  that can be attached to several inbounds on purpose.
- *spiderX format* - the panel derives a per-client `spx` that always starts
  with `/`.
- *Reading the Xray binary version locally* - the status API already reports
  the version of the running core.
- *Guessing default credentials* - the tool never tries passwords; it only
  flags admin/admin when you ran it with those.

## Why the Xray check exists

Two changes in the official Xray-core REALITY server break clients that worked
before, and nothing in the panel says so:

1. **26.7.11 - 26.7.28:** REALITY servers default `minClientVer` to 26.3.27
   ([Xray-core af7eb680](https://github.com/XTLS/Xray-core/commit/af7eb68028732a8ee3c0e5d6ab2b8a657bb2e770)).
   Clients that do not send an Xray version (sing-box, mihomo) and Xray clients
   older than 26.3.27 are refused unless the inbound sets `minClientVer`
   explicitly.
2. **26.9.8 and later:** the server rejects any ClientHello that does not carry
   an X25519MLKEM768 key share before the optional X25519 one
   ([XTLS/REALITY 8cdf7bf9](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8),
   pulled into Xray-core by
   [47cfe999](https://github.com/XTLS/Xray-core/commit/47cfe9994a6b39b1f673ba35e62b091bcce15a71), first in
   v26.9.8; that tag was deleted upstream, v26.9.9 is the first published
   release). The same release comments the `minClientVer` default out again. A
   refused hello is treated as a non-REALITY visitor and forwarded to the
   target, so the client sees the target's real certificate.

Test matrix (official binaries, everything on loopback, target `www.nvidia.com`,
4 requests per cell; script in [`tools/reality-matrix`](tools/reality-matrix)):

| Server | Xray client chrome / firefox / safari | Xray client ios / edge / qq | sing-box 1.12.12 and 1.14.4, any fp | mihomo 1.19.33 | mihomo + `support-x25519mlkem768: true`, chrome |
|---|---|---|---|---|---|
| 26.6.27 | ok | ok | ok | ok | ok |
| 26.7.28 | ok | ok | refused | refused | refused |
| 26.9.9 | ok | **refused** | **refused** | **refused** | ok |
| 26.10.31 | ok | **refused** | **refused** | **refused** | ok |

Xray clients 26.6.27 and 26.10.31 behave the same. `android` and `360`
failed against every server in this setup, `random`/`randomized*` pick a
different hello per connection and work only sometimes. The same result end
to end through a panel: on 3x-ui 3.11.0 (bundled Xray 26.10.21) and still-ui
1.3.0 (Xray 26.10.31), an inbound with `fp=ios` gave 0/3 for an Xray client
with fp ios, 3/3 with chrome and safari, and 0/3 for sing-box 1.14.4.

What to do, as the findings say: switch the link fingerprint to chrome,
firefox or safari, or pin Xray 26.6.27 in the panel's Xray version switcher.
The ML-KEM hello is bigger - measured with Xray 26.10.31: chrome 1820,
firefox 1889, safari 1537 bytes against 517 for ios/edge/qq - and needs two
TCP segments, which a few mobile networks handle badly. The panel's own Clash
subscription already sets `support-x25519mlkem768: true` for mihomo clients;
a host with "Mihomo X25519" on turns that off.

A patched core that still accepts old hellos reports the same version string;
the tool cannot tell, so read the `xray` findings with that in mind.

## Development

```
go vet ./...
go test ./...
```

Messages live in `internal/i18n/catalog.go`, in English and Russian. A test
fails when a message has no Russian text, when the two texts use different
format verbs, or when code uses an ID the catalog lacks.

`testdata/` holds answers recorded from throwaway 3x-ui 3.11.0 and still-ui
1.3.0 panels, with UUIDs, keys, passwords and GUIDs replaced by fake values.
`internal/doctor` replays them through a fake panel that enforces the same
CSRF and session rules and fails the test on any request outside the
read-only set above.

## License

MIT. Not affiliated with the 3x-ui or Xray-core projects.

