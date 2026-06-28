# Atom Loops

Proof of Concept of an atomic deployment for Linux devices based EROFS + dm-verity + UKI.

> [!CAUTION]
> This is just a **Proof of Concept** that demonstrates the whole deploy chain of Atom Loops works but proper development is needed. **DO NOT** use this in production, are just a bunch of hardcoded scripts and terrible things may happen when used in production. Proper software is being development.

## What it demonstrates

The full chain from firmware to login prompt, with cryptographic verification at every step:

1. **UEFI firmware** loads the UKI from the ESP partition
2. **UKI** contains: Linux kernel + Go initramfs + kernel cmdline with `ATOM_ROOT_HASH=<sha256>`
3. **Go initramfs** (`scripts/boot/initramfs-main.go`) takes over:
   - Mounts `/proc`, `/sys`, `/dev`
   - Loads 17 kernel modules from CPIO (virtio, dm-verity, erofs, overlay, loop, crc32c...)
   - Finds the root block device from cmdline (`root=/dev/vdb`)
   - Extracts the root hash from cmdline (`ATOM_ROOT_HASH=...`)
   - Sets up a loop device for the embedded hash tree (`losetup -r /dev/loop0 /boot/rootfs/rootfs-v1.hash`)
   - Activates dm-verity: `veritysetup open /dev/vdb atom-verity /dev/loop0 <root_hash>`
   - Mounts the verified device as EROFS read-only
   - Looks for a persistent `/var` partition (marked with `.atom-var`); when found, assembles "Model A": persistent `/var`, an `/etc` overlay whose upper lives in `/var`, a `/home` bind of `/var/home`, and a tmpfs `/tmp`. With no such partition it falls back to an ephemeral tmpfs `/var`.
   - Reads `deployment.json` from the mounted rootfs (WAL state)
   - Moves `/dev`, `/proc`, `/sys` into the new root
   - `switch_root` -> `/sbin/init`
4. **dm-verity** verifies every 4KB block read from the rootfs against the SHA256 hash tree. The root hash is in the UKI cmdline, which is part of the signed PE binary. Tamper with any single byte of the rootfs and the kernel rejects it.
5. **EROFS** is inherently read-only. The base system is never modified in place; it is replaced wholesale on update. Writable state lives outside the verified root: `/var` (and `/home`, bound to `/var/home`) is persistent on its own partition, `/etc` is a thin overlay whose changes are stored in `/var`, and only `/tmp` is RAM-backed. Without a persistent partition the whole writable layer falls back to tmpfs and is clean on every boot.

The root hash never touches untrusted storage. It is embedded in the UKI, which is a PE binary that can be signed with Secure Boot Authenticode. This makes the entire rootfs integrity chain: firmware -> UKI signature -> cmdline root hash>  dm-verity -> EROFS blocks.

## Artifacts

Rootfs and hash tree come from [Singularity OS releases](https://github.com/singularityos-lab/os/releases). The initramfs and UKI are built locally against the Void Linux musl kernel 6.12.82_1 (just because Singularity Linux kernel does not include all required features yet).

## Quick start

Download the latest Singularity OS release, build everything and start with qemu:

```bash
bash scripts/build/fetch-release.sh
bash scripts/test/qemu-terminal.sh
```

You should see the boot chain end with `Sinty OS` and a login prompt on ttyS0.

Then test with QEMU (1GB RAM, OVMF, KVM):

```bash
bash scripts/test/qemu-terminal.sh
```

## License

MIT