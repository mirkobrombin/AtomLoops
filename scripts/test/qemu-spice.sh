#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

DISK="out/disk.img"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="out/ovmf_vars.fd"
PORT="${1:-5930}"

[ -f "${DISK}" ] || { echo "[qemu-spice] ${DISK} missing (run atom-install --image)"; exit 1; }
[ -f "${OVMF_VARS}" ] || cp /usr/share/OVMF/OVMF_VARS_4M.fd "${OVMF_VARS}"

echo "[qemu-spice] connect with:  remote-viewer spice://127.0.0.1:${PORT}"
echo "[qemu-spice] (Ctrl+C here to stop the VM)"

exec qemu-system-x86_64 \
  -machine type=q35 \
  -m 2048 -smp 2 \
  -accel kvm \
  -drive if=pflash,format=raw,readonly=on,file="${OVMF_CODE}" \
  -drive if=pflash,format=raw,file="${OVMF_VARS}" \
  -drive if=virtio,format=raw,file="${DISK}" \
  -device virtio-vga \
  -spice port=${PORT},disable-ticketing=on \
  -device virtio-serial \
  -chardev spicevmc,id=vdagent,name=vdagent \
  -device virtserialport,chardev=vdagent,name=com.redhat.spice.0 \
  -serial file:out/qemu-spice-boot.log \
  -display none
