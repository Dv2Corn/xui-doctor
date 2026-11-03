#!/bin/bash
# Download the official binaries matrix.sh uses (linux amd64) next to this script.
set -eu
cd "$(dirname "$0")"
for v in 26.10.31 26.9.9 26.7.28 26.6.27; do
  mkdir -p "x$v"
  curl -fsSL -o "x$v.zip" "https://github.com/XTLS/Xray-core/releases/download/v$v/Xray-linux-64.zip"
  unzip -o -q "x$v.zip" xray -d "x$v"
  "x$v/xray" version | head -1
done
for v in 1.12.12 1.14.4; do
  mkdir -p "sb$v"
  curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v$v/sing-box-$v-linux-amd64.tar.gz" | tar -xz -C "sb$v" --strip-components=1
  "sb$v/sing-box" version | head -1
done
curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-compatible-v1.19.33.gz" | gunzip > mihomo
chmod +x mihomo && ./mihomo -v | head -1
