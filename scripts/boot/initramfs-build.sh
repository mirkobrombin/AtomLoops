#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

SRC="scripts/boot/initramfs-main.go"
OUT="out/initramfs.cpio.gz"
VOID_ROOTFS="out/void-rootfs"
VOID_MODS="${VOID_ROOTFS}/usr/lib/modules/6.12.82_1"

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
    for applet in sh modprobe insmod rmmod mount umount mkdir mknod ln ls reboot poweroff halt losetup; do
        ln -sf busybox "out/initramfs-staging/bin/${applet}" &>/dev/null || true
    done
fi

# Copy veritysetup, losetup and all their musl shared libs from Void rootfs.
DST_LIB="out/initramfs-staging/lib"
copy_void_lib() {
    local src="$1"
    local dst_dir="$2"
    local real=$(readlink -f "${src}")
    [ ! -f "$real" ] && return 1
    local real_name=$(basename "$real")
    local link_name=$(basename "${src}")
    [ ! -f "${dst_dir}/${real_name}" ] && cp "${real}" "${dst_dir}/${real_name}"
    [ "$link_name" != "$real_name" ] && [ ! -e "${dst_dir}/${link_name}" ] && \
        ln -sf "${real_name}" "${dst_dir}/${link_name}"
    return 0
}

if [ -d "${VOID_ROOTFS}" ]; then
    echo "[initramfs-build] using Void musl binaries for dm-verity"

    for bin in veritysetup losetup; do
        for dir in usr/sbin usr/bin sbin bin; do
            if [ -f "${VOID_ROOTFS}/${dir}/${bin}" ]; then
                cp "${VOID_ROOTFS}/${dir}/${bin}" "out/initramfs-staging/sbin/${bin}"
                chmod 755 "out/initramfs-staging/sbin/${bin}"
                echo "[initramfs-build] copied ${bin} from Void"
                break
            fi
        done
    done

    copy_void_lib "${VOID_ROOTFS}/lib/libc.so" "${DST_LIB}" || \
    copy_void_lib "${VOID_ROOTFS}/usr/lib/libc.so" "${DST_LIB}" || true

    for lib_name in \
        libcryptsetup.so.12 \
        libpopt.so.0 \
        libblkid.so.1 \
        libuuid.so.1 \
        libdevmapper.so.1.02 \
        libcrypto.so.3 \
        libjson-c.so.5 \
        libudev.so.1 \
        libsmartcols.so.1; do
        for vlib in "${VOID_ROOTFS}/lib/${lib_name}"* "${VOID_ROOTFS}/usr/lib/${lib_name}"*; do
            [ -e "$vlib" ] || [ -L "$vlib" ] || continue
            copy_void_lib "$vlib" "${DST_LIB}" || true
        done
    done

    ln -sf libc.so out/initramfs-staging/lib/ld-musl-x86_64.so.1
    mkdir -p out/initramfs-staging/lib64
    ln -sf ../lib/ld-musl-x86_64.so.1 out/initramfs-staging/lib64/ld-linux-x86-64.so.2
    echo "[initramfs-build] set up musl dynamic linker"
else
    echo "[initramfs-build] WARNING: Void rootfs not found, dm-verity tools skipped"
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

if [ -d "${VOID_MODS}/kernel" ]; then
    ver_name="6.12.82_1"
    echo "[initramfs-build] copying+decompressing Void modules from ${VOID_MODS}"
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
        "fs/overlayfs/overlay.ko"; do
        found=$(find "${VOID_MODS}/kernel" -path "*/${mod_spec}*" -type f 2>/dev/null | head -1)
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