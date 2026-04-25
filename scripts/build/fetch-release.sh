#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

RELEASE="v1.0.3"
REPO="singularityos-lab/os"
OUT_DIR="out"

echo "[fetch-release] downloading release ${RELEASE} from ${REPO}"

mkdir -p "${OUT_DIR}"

gh release download "${RELEASE}" \
  --repo "${REPO}" \
  --pattern "kernelcache.efi" \
  --pattern "rootfs.erofs" \
  --pattern "rootfs.hash" \
  --pattern "verity-output.txt" \
  --dir "${OUT_DIR}" \
  --clobber

ROOT_HASH=$(grep 'Root hash' "${OUT_DIR}/verity-output.txt" | awk '{print $3}')
echo "[fetch-release] root hash: ${ROOT_HASH}"
echo "${ROOT_HASH}" > "${OUT_DIR}/rootfs-v1.roothash"

mv "${OUT_DIR}/rootfs.hash" "${OUT_DIR}/rootfs-v1.hash"
mv "${OUT_DIR}/rootfs.erofs" "${OUT_DIR}/rootfs-v1.erofs"

echo "[fetch-release] rebuilding initramfs with new hash tree"
bash scripts/boot/initramfs-build.sh

echo "[fetch-release] rebuilding UKI with root hash ${ROOT_HASH}"
bash scripts/build/build-kernelcache.sh

echo "[fetch-release] rebuilding ESP"
bash scripts/boot/esp-build.sh

echo "[fetch-release] done. Test with: bash scripts/test/qemu-terminal.sh"