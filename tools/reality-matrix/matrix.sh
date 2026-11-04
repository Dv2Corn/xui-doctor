#!/bin/bash
# REALITY compatibility matrix: official Xray-core servers x client cores and
# uTLS fingerprints. Everything listens on 127.0.0.1; keys are generated per run.
#
# Layout (fetch.sh creates it): x<ver>/xray for every Xray version, sb<ver>/sing-box,
# ./mihomo. Each cell prints "successes/TRIALS" for fresh HTTPS requests
# through the client's SOCKS port.
#
# Env: SERVERS, XCLIENTS, XFPS (space-separated), TRIALS (default 3),
# DEST (REALITY target, default www.nvidia.com), URL (probe URL),
# MINVER (sets the server's "minClientVer").
# Note: with DEST=www.microsoft.com, Xray 26.6.27 and 26.7.28 servers failed for every
# client in our runs, so the default target is www.nvidia.com.
set -u
cd "$(dirname "$0")"
DEST=${DEST:-www.nvidia.com}
URL=${URL:-https://www.gstatic.com/generate_204}
KEYS=$(x26.10.31/xray x25519)
PRIV=$(echo "$KEYS" | sed -n 's/^PrivateKey: *//p')
PUB=$(echo "$KEYS" | sed -n 's/^Password (PublicKey): *//p')
UUID=$(x26.10.31/xray uuid)
SID=0123abcd
MINJSON=""
[ -n "${MINVER:-}" ] && MINJSON=",\"minClientVer\":\"$MINVER\""
mkdir -p run; rm -rf run/*
# Stop every child (servers and clients) however the script ends.
trap 'kill $(jobs -p) 2>/dev/null' EXIT

server_cfg() { # port
cat <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":$1,"protocol":"vless",
  "settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
  "streamSettings":{"network":"tcp","security":"reality",
   "realitySettings":{"target":"$DEST:443","serverNames":["$DEST"],"privateKey":"$PRIV","shortIds":["$SID"]$MINJSON}}}],
 "outbounds":[{"protocol":"freedom"}]}
EOF
}
xray_client_cfg() { # sport cport fp
cat <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":$2,"protocol":"socks","settings":{"udp":false}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":$1,"users":[{"id":"$UUID","flow":"xtls-rprx-vision","encryption":"none"}]}]},
  "streamSettings":{"network":"tcp","security":"reality",
   "realitySettings":{"serverName":"$DEST","fingerprint":"$3","publicKey":"$PUB","shortId":"$SID"}}}]}
EOF
}
singbox_cfg() { # sport cport fp
cat <<EOF
{"log":{"level":"warn"},
 "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":$2}],
 "outbounds":[{"type":"vless","server":"127.0.0.1","server_port":$1,"uuid":"$UUID","flow":"xtls-rprx-vision",
  "tls":{"enabled":true,"server_name":"$DEST","utls":{"enabled":true,"fingerprint":"$3"},
   "reality":{"enabled":true,"public_key":"$PUB","short_id":"$SID"}}}]}
EOF
}
mihomo_cfg() { # sport cport fp mlkem(true|false|omit)
  local extra=""
  [ "$4" != omit ] && extra=", support-x25519mlkem768: $4"
cat <<EOF
mixed-port: $2
bind-address: 127.0.0.1
allow-lan: false
mode: global
log-level: warning
dns: {enable: false}
proxies:
  - {name: r, type: vless, server: 127.0.0.1, port: $1, uuid: $UUID, network: tcp, tls: true, udp: false, flow: xtls-rprx-vision, servername: $DEST, client-fingerprint: $3, reality-opts: {public-key: $PUB, short-id: $SID$extra}}
proxy-groups: [{name: GLOBAL, type: select, proxies: [r]}]
rules: ["MATCH,r"]
EOF
}

probe() { # cport -> "ok/N" over TRIALS fresh requests
  local n=${TRIALS:-3} ok=0 i c
  for i in $(seq 1 $n); do
    c=$(curl -s -o /dev/null -w '%{http_code}' -m 10 -x socks5h://127.0.0.1:$1 "$URL" 2>/dev/null || true)
    [ "$c" = 204 ] && ok=$((ok+1))
  done
  echo "$ok/$n"
}
port_open() { (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null; }
wait_port() { for _ in $(seq 1 40); do port_open $1 && return 0; sleep 0.1; done; return 1; }
# Xray binds with SO_REUSEPORT, so a leftover process on a port would silently
# take part of the connections: refuse to run instead.
for p in $(seq 24401 24410) $(seq 25001 25080); do
  port_open $p && { echo "port $p is already in use; stop leftover test processes first" >&2; exit 1; }
done

SERVERS=${SERVERS:-"26.10.31 26.9.9 26.7.28 26.6.27"}
XCLIENTS=${XCLIENTS:-"26.10.31 26.6.27"}
XFPS=${XFPS:-"chrome firefox safari ios android edge 360 qq random randomized randomizednoalpn"}
SPORT=24400
for SV in $SERVERS; do
  SPORT=$((SPORT+1))
  server_cfg $SPORT > run/server-$SV.json
  x$SV/xray run -c run/server-$SV.json > run/server-$SV.log 2>&1 &
  SPID=$!
  wait_port $SPORT || { echo "server $SV did not start"; cat run/server-$SV.log; exit 1; }
  CPORT=25000
  row() { printf '%-9s %-17s %-20s %s\n' "$SV" "$1" "$2" "$3"; }
  for XC in $XCLIENTS; do
    for fp in $XFPS; do
      CPORT=$((CPORT+1))
      xray_client_cfg $SPORT $CPORT $fp > run/c.json
      x$XC/xray run -c run/c.json > run/c-$SV-$XC-$fp.log 2>&1 &
      CP=$!; wait_port $CPORT; r=$(probe $CPORT); kill $CP 2>/dev/null; wait $CP 2>/dev/null
      row "xray-$XC" "$fp" "$r"
    done
  done
  for SB in 1.12.12 1.14.4; do
    for fp in chrome firefox safari ios; do
      CPORT=$((CPORT+1))
      singbox_cfg $SPORT $CPORT $fp > run/sb.json
      sb$SB/sing-box run -c run/sb.json > run/sb-$SV-$SB-$fp.log 2>&1 &
      CP=$!; wait_port $CPORT; r=$(probe $CPORT); kill $CP 2>/dev/null; wait $CP 2>/dev/null
      row "sing-box-$SB" "$fp" "$r"
    done
  done
  for ml in omit true; do
    for fp in chrome ios; do
      CPORT=$((CPORT+1))
      mkdir -p run/mh; mihomo_cfg $SPORT $CPORT $fp $ml > run/mh/config.yaml
      ./mihomo -d run/mh > run/mh-$SV-$ml-$fp.log 2>&1 &
      CP=$!; wait_port $CPORT; r=$(probe $CPORT); kill $CP 2>/dev/null; wait $CP 2>/dev/null
      row "mihomo-1.19.33" "$fp mlkem=$ml" "$r"
    done
  done
  kill $SPID; wait $SPID 2>/dev/null
done
