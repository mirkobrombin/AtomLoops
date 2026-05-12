#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

ROOTFS_DIR="out/void-rootfs"
VMLINUX="${ATOM_KERNEL:-${ROOTFS_DIR}/boot/vmlinuz-6.12.82_1}"
INITRAMFS="out/initramfs.cpio.gz"
ROOT_HASH=$(cat out/rootfs-v1.roothash)
CMDLINE="console=ttyS0 console=tty0 ATOM_ROOT_HASH=${ROOT_HASH} ro"
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
    echo "[build-kernelcache] ukify not found, using systemd-stub + objcopy"
    STUB="/usr/lib/systemd/boot/efi/linuxx64.efi.stub"
    BASE=$((16#$(objdump -p "${STUB}" | awk '/ImageBase/{print $2}')))
    vma() { printf "0x%x" $((BASE + $1)); }
    printf '%s' "${CMDLINE}" > out/cmdline.txt
    objcopy \
        --add-section .cmdline=out/cmdline.txt --change-section-vma .cmdline=$(vma 0x110000) \
        --add-section .linux="${VMLINUX}" --change-section-vma .linux=$(vma 0x200000) \
        --add-section .initrd="${INITRAMFS}" --change-section-vma .initrd=$(vma 0x2000000) \
        "${STUB}" "${OUTPUT}"
fi

echo "[build-kernelcache] done: ${OUTPUT}"
