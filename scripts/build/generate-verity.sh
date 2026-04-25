#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

IMAGE="out/rootfs-v1.erofs"
HASH_TREE="out/rootfs-v1.hash"
ROOT_HASH_FILE="out/rootfs-v1.roothash"

echo "[generate-verity] generating dm-verity hash tree for ${IMAGE}"

truncate -s "$(stat -c %s "${IMAGE}")" "${HASH_TREE}"

/usr/sbin/veritysetup format "${IMAGE}" "${HASH_TREE}" | tee "${ROOT_HASH_FILE}.raw"

grep 'Root hash' "${ROOT_HASH_FILE}.raw" | awk '{print $3}' > "${ROOT_HASH_FILE}"

echo "[generate-verity] root hash saved to ${ROOT_HASH_FILE}"
echo "[generate-verity] hash tree image ${HASH_TREE}"
