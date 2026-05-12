#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

ESP="out/esp.img"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="out/ovmf_vars.fd"
SYSTEM="out/system.ext4"
VAR="out/var.img"

echo "[qemu-terminal] launching QEMU in terminal mode"
echo ""
echo "Press Ctrl+A then X to exit QEMU"
echo ""

qemu-system-x86_64 \
  -machine type=q35 \
  -m 1024 -smp 2 \
  -accel kvm \
  -drive if=pflash,format=raw,readonly=on,file="${OVMF_CODE}" \
  -drive if=pflash,format=raw,file="${OVMF_VARS}" \
  -drive if=virtio,format=raw,file="${ESP}",readonly=on \
  -drive if=virtio,format=raw,file="${SYSTEM}",readonly=on,index=1 \
  -drive if=virtio,format=raw,file="${VAR}",index=2 \
  -nographic

echo "[qemu-terminal] QEMU stopped"
