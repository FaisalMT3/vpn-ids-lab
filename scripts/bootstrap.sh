#!/usr/bin/env bash
set -euo pipefail
LAB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ROOT_DIR="$LAB_DIR/runtime/rootfs"
DOWNLOAD_DIR="$LAB_DIR/runtime/downloads"
mkdir -p "$ROOT_DIR" "$DOWNLOAD_DIR"
cd "$DOWNLOAD_DIR"
ARCHIVE=alpine-minirootfs-3.22.0-x86_64.tar.gz
BASE_URL=https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64
curl -fL -o "$ARCHIVE" "$BASE_URL/$ARCHIVE"
curl -fL -o "$ARCHIVE.sha256" "$BASE_URL/$ARCHIVE.sha256"
sha256sum -c "$ARCHIVE.sha256"
tar -xzf "$ARCHIVE" -C "$ROOT_DIR"
cp /etc/resolv.conf "$ROOT_DIR/etc/resolv.conf"
unshare --user --map-root-user --mount --propagation private \
  chroot "$ROOT_DIR" /sbin/apk add --no-cache suricata wireguard-tools iproute2 tcpdump iptables curl python3 ethtool
