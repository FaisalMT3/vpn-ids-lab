#!/usr/bin/env bash
set -euo pipefail
LAB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ${1:-} != --inside ]]; then
  exec unshare --user --map-root-user --net --mount --pid --fork --kill-child --propagation private "$0" --inside
fi
ROOT_DIR="$LAB_DIR/runtime/rootfs"
mkdir -p "$ROOT_DIR"/{lab,proc,dev,run,sys}
mount --bind "$ROOT_DIR" "$ROOT_DIR"
mount --bind "$LAB_DIR" "$ROOT_DIR/lab"
for device in null zero random urandom; do
  touch "$ROOT_DIR/dev/$device"
  mount --bind "/dev/$device" "$ROOT_DIR/dev/$device"
done
mount -t proc proc "$ROOT_DIR/proc"
mount -t tmpfs tmpfs "$ROOT_DIR/run"
exec chroot "$ROOT_DIR" /usr/bin/env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/python3 /lab/scripts/lab.py
