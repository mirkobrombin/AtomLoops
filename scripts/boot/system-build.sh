#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

SYS="out/system.ext4"
STAGE="out/system-staging"
EROFS="out/rootfs-v1.erofs"
HASH="out/rootfs-v1.hash"

[ -f "${EROFS}" ] || { echo "[system-build] missing ${EROFS} (run fetch-release.sh)"; exit 1; }
[ -f "${HASH}" ]  || { echo "[system-build] missing ${HASH}"; exit 1; }

echo "[system-build] assembling Atom Loops system partition (file-based rootfs)"

rm -rf "${STAGE}" "${SYS}"
mkdir -p "${STAGE}/boot/rootfs"

cp "${EROFS}" "${STAGE}/boot/rootfs/rootfs-active.erofs"
cp "${HASH}"  "${STAGE}/boot/rootfs/rootfs-active.hash"

cat > "${STAGE}/boot/rootfs/deployment.json" <<'EOF'
{
  "rootfs": {
    "current": "v1",
    "pending": "",
    "rollback": "",
    "boot_attempts": 0,
    "max_attempts": 3,
    "last_known_good": "v1"
  },
  "kernelcache": {
    "state": "stable",
    "stable_boots": 0,
    "stable_threshold": 3,
    "format": "uki"
  },
  "security": {
    "level": 2,
    "dm_verity": true,
    "secure_boot": false
  }
}
EOF
cp "${STAGE}/boot/rootfs/deployment.json" "${STAGE}/boot/rootfs/deployment.json.bak"

SZ=$(du -sm "${STAGE}" | cut -f1)
SZ=$((SZ + 64))
mke2fs -q -t ext4 -L atom-system -d "${STAGE}" "${SYS}" "${SZ}M"

echo "[system-build] done: ${SYS}"
ls -lh "${SYS}"
