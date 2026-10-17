#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

SRC="./cmd/atom-init"
OUT="out/initramfs.cpio.gz"
VOID_ROOTFS="out/void-rootfs"
VOID_MODS="${VOID_ROOTFS}/usr/lib/modules/6.12.82_1"
MODS_DIR="${ATOM_MODS:-${VOID_MODS}}"
MOD_VER="$(basename "${MODS_DIR}")"

echo "[initramfs-build] compiling ${SRC}"

if command -v musl-gcc &>/dev/null; then
    CC=musl-gcc CGO_ENABLED=1 go build -ldflags='-s -w -linkmode external -extldflags -static' \
        -o out/initramfs-init "${SRC}"
else
    CGO_ENABLED=0 go build -ldflags='-s -w' -o out/initramfs-init "${SRC}"
fi

echo "[initramfs-build] assembling initramfs ${OUT}"

rm -rf out/initramfs-staging
mkdir -p out/initramfs-staging/{bin,sbin,lib/modules,proc,sys,dev,tmp,newroot,root,boot,rootfs,lib64}

cp out/initramfs-init out/initramfs-staging/init
chmod 0755 out/initramfs-staging/init
cp out/initramfs-init out/initramfs-staging/sbin/init
chmod 0755 out/initramfs-staging/sbin/init

BB=""
for path in /bin/busybox /usr/bin/busybox /usr/sbin/busybox; do
    if [ -x "$path" ]; then BB="$path"; break; fi
done
if [ -n "${BB}" ]; then
    echo "[initramfs-build] copying busybox from ${BB}"
    cp "${BB}" out/initramfs-staging/bin/busybox
    chmod +x out/initramfs-staging/bin/busybox
    for applet in sh; do
        ln -sf busybox "out/initramfs-staging/bin/${applet}" &>/dev/null || true
    done
fi

# Embed the dm-verity hash tree inside the initramfs.
if [ -f "out/rootfs-v1.hash" ]; then
    echo "[initramfs-build] embedding dm-verity hash tree"
    mkdir -p out/initramfs-staging/boot/rootfs
    cp out/rootfs-v1.hash out/initramfs-staging/boot/rootfs/rootfs-v1.hash
fi
if [ -f "out/rootfs-v1.roothash" ]; then
    cp out/rootfs-v1.roothash out/initramfs-staging/boot/rootfs/rootfs-v1.roothash
fi

# Copy kernel modules from Void rootfs (matching kernel 6.12.82_1).
MOD_OK=false

if [ -d "${MODS_DIR}/kernel" ]; then
    ver_name="${MOD_VER}"
    echo "[initramfs-build] copying+decompressing modules from ${MODS_DIR}"
    mkdir -p "out/initramfs-staging/lib/modules/${ver_name}"
    for mod_spec in \
        "drivers/virtio/virtio.ko" \
        "drivers/virtio/virtio_ring.ko" \
        "drivers/virtio/virtio_mmio.ko" \
        "drivers/virtio/virtio_pci.ko" \
        "drivers/virtio/virtio_pci_modern_dev.ko" \
        "drivers/virtio/virtio_pci_legacy_dev.ko" \
        "drivers/block/virtio_blk.ko" \
        "drivers/block/loop.ko" \
        "lib/reed_solomon/reed_solomon.ko" \
        "lib/libcrc32c.ko" \
        "drivers/md/dm-mod.ko" \
        "drivers/md/dm-bufio.ko" \
        "drivers/md/dm-verity.ko" \
        "crypto/crc32c_generic.ko" \
        "crypto/xxhash_generic.ko" \
        "fs/erofs/erofs.ko" \
        "fs/overlayfs/overlay.ko" \
        "crc16.ko" \
        "fs/mbcache.ko" \
        "fs/jbd2/jbd2.ko" \
        "fs/ext4/ext4.ko"; do
        found=$(find "${MODS_DIR}/kernel" -path "*/${mod_spec}*" -type f 2>/dev/null | head -1)
        [ -z "${found}" ] && continue
        dest="out/initramfs-staging/lib/modules/${ver_name}/$(basename "$mod_spec")"
        if [[ "${found}" == *.xz ]]; then
            xzcat -f "${found}" > "${dest}" 2>/dev/null && echo "[initramfs-build] decompressed ${mod_spec}"
        elif [[ "${found}" == *.zst ]]; then
            zstd -d "${found}" -o "${dest}" 2>/dev/null && echo "[initramfs-build] decompressed ${mod_spec}"
        elif [[ "${found}" == *.gz ]]; then
            gunzip -c "${found}" > "${dest}" 2>/dev/null && echo "[initramfs-build] decompressed ${mod_spec}"
        else
            cp -a "${found}" "${dest}" 2>/dev/null && echo "[initramfs-build] copied ${mod_spec}"
        fi
    done
    MOD_OK=true
fi

if [ "$MOD_OK" = "false" ]; then
    echo "[initramfs-build] WARNING: no kernel modules found"
fi

(
    cd out/initramfs-staging
    find . | cpio -o -H newc | gzip > "../../${OUT}"
)

echo "[initramfs-build] done: ${OUT}"
ls -lh "${OUT}"