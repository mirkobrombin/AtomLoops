#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

ROOTFS_DIR="out/void-rootfs"
VMLINUX="${ROOTFS_DIR}/boot/vmlinuz-6.12.82_1"
INITRAMFS="out/initramfs.cpio.gz"
ROOT_HASH=$(cat out/rootfs-v1.roothash)
CMDLINE="console=ttyS0 root=/dev/vdb ATOM_ROOT_HASH=${ROOT_HASH} ro"
OUTPUT="out/kernelcache-v1.efi"

echo "[build-kernelcache] assembling UKI ${OUTPUT}"
echo "[build-kernelcache] kernel: ${VMLINUX}"
echo "[build-kernelcache] root hash: ${ROOT_HASH}"

if [ ! -f "${INITRAMFS}" ]; then
    echo "[build-kernelcache] WARNING: initramfs ${INITRAMFS} not found. Run initramfs-build first."
    exit 1
fi

if [ ! -f "${VMLINUX}" ]; then
    echo "[build-kernelcache] ERROR: kernel ${VMLINUX} not found. Run build-rootfs-void.sh first."
    exit 1
fi

if command -v ukify &>/dev/null; then
    ukify build \
        --linux="${VMLINUX}" \
        --initrd="${INITRAMFS}" \
        --cmdline="${CMDLINE}" \
        --output="${OUTPUT}"
else
    echo "[build-kernelcache] ukify not found, using objcopy fallback"
    cp "${VMLINUX}" "${OUTPUT}"
    objcopy \
        --add-section .initrd="${INITRAMFS}" \
        --set-section-flags .initrd=readonly,data \
        --add-section .cmdline=<(printf '%s' "${CMDLINE}") \
        --set-section-flags .cmdline=readonly,data \
        "${OUTPUT}" "${OUTPUT}"
fi

echo "[build-kernelcache] done: ${OUTPUT}"
