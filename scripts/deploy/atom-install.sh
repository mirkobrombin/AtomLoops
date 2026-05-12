#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

ESP="out/esp.img"
SYSTEM="out/system.ext4"
VAR="out/var.img"

for f in "${ESP}" "${SYSTEM}" "${VAR}"; do
    [ -f "${f}" ] || { echo "[atom-install] missing ${f} (build esp/system/var first)"; exit 1; }
done

TARGET="${1:-}"
[ -n "${TARGET}" ] || { echo "usage: atom-install --image [out/disk.img] | /dev/sdX"; exit 1; }

if [ "${TARGET}" = "--image" ]; then
    OUT="${2:-out/disk.img}"
    GENIMAGE="$(command -v genimage || true)"
    [ -n "${GENIMAGE}" ] || GENIMAGE="${HOME}/Projects/personal/singularity-os/buildroot-build/host/bin/genimage"
    [ -x "${GENIMAGE}" ] || { echo "[atom-install] genimage not found"; exit 1; }

    echo "[atom-install] assembling installable disk image"
    rm -rf out/genimage-tmp "${OUT}"
    mkdir -p out/genimage-tmp
    "${GENIMAGE}" \
        --config scripts/deploy/genimage.cfg \
        --inputpath out \
        --outputpath out \
        --tmppath out/genimage-tmp
    [ "${OUT}" != "out/disk.img" ] && mv -f out/disk.img "${OUT}"
    echo "[atom-install] done: ${OUT}"
    ls -lh "${OUT}"
    exit 0
fi

DEV="${TARGET}"
[ -b "${DEV}" ] || { echo "[atom-install] ${DEV} is not a block device"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "[atom-install] provisioning a real disk needs root"; exit 1; }
command -v sfdisk >/dev/null || { echo "[atom-install] sfdisk (util-linux) required"; exit 1; }

ESP_MB=$(( ( $(stat -c%s "${ESP}")    + 1048575) / 1048576 ))
SYS_MB=$(( ( $(stat -c%s "${SYSTEM}") + 1048575) / 1048576 ))

echo "[atom-install] WARNING: this will ERASE ${DEV}"
sfdisk "${DEV}" <<EOF
label: gpt
start=1MiB,                 size=${ESP_MB}MiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=ESP, bootable
start=$((1 + ESP_MB))MiB,   size=${SYS_MB}MiB, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=atom-system
start=$((1 + ESP_MB + SYS_MB))MiB,                  type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=atom-var
EOF

partprobe "${DEV}" 2>/dev/null || true
P() { case "${DEV}" in *[0-9]) echo "${DEV}p$1";; *) echo "${DEV}$1";; esac; }

echo "[atom-install] writing ESP and system images"
dd if="${ESP}"    of="$(P 1)" bs=4M conv=fsync status=none
dd if="${SYSTEM}" of="$(P 2)" bs=4M conv=fsync status=none
echo "[atom-install] creating empty persistent /var"
mke2fs -q -t ext4 -L atom-var "$(P 3)"
tmp="$(mktemp -d)"
mount "$(P 3)" "${tmp}"
mkdir -p "${tmp}"/{home,etc-upper,etc-work,lib,cache,log,spool,tmp,run}
chmod 1777 "${tmp}/tmp"
: > "${tmp}/.atom-var"
umount "${tmp}"; rmdir "${tmp}"

echo "[atom-install] done: provisioned ${DEV}"
