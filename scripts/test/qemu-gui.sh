#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

ESP="out/esp.img"
UKI="out/kernelcache-v1.efi"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="out/ovmf_vars.fd"
SYSTEM="out/system.ext4"
VAR="out/var.img"

echo "[qemu-gui] launching QEMU with VNC display"
echo ""
echo "Press Ctrl+C to stop QEMU"
echo ""

qemu-system-x86_64 \
  -machine type=q35 \
  -m 1024 -smp 2 \
  -accel kvm \
  -vga std \
  -drive if=pflash,format=raw,readonly=on,file="${OVMF_CODE}" \
  -drive if=pflash,format=raw,file="${OVMF_VARS}" \
  -drive if=virtio,format=raw,file="${ESP}",readonly=on \
  -drive if=virtio,format=raw,file="${SYSTEM}",readonly=on,index=1 \
  -drive if=virtio,format=raw,file="${VAR}",index=2 \
  -vnc :0,password=off \
  -serial file:out/qemu-gui-boot.log \
  > out/qemu-vnc.log 2>&1

echo "[qemu-gui] QEMU stopped"
