#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

ESP="out/esp.img"
UKI="out/kernelcache-v1.efi"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
OVMF_VARS="ovmf_vars.fd"
ROOTFS="out/rootfs-v1.erofs"

echo "[esp-build] creating ESP FAT32 image"

rm -f "${ESP}"

dd if=/dev/zero of="${ESP}" bs=1M count=64 2>/dev/null
mformat -i "${ESP}" -F -v "ESP" ::
mmd -i "${ESP}" ::/EFI
mmd -i "${ESP}" ::/EFI/BOOT
mcopy -i "${ESP}" "${UKI}" ::/EFI/BOOT/BOOTX64.EFI

echo "[esp-build] verifying ESP contents"
mdir -i "${ESP}" ::/EFI/BOOT/

echo "[esp-build] done: ${ESP}"
ls -lh "${ESP}"
