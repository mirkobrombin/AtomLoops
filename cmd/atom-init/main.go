// atom-init is the reference initramfs init of Atom Loops. It runs the boot
// package end to end: find the root that matches the signed hash, lay out
// /var, union the verified firmware and switch to the real init. A
// distribution can ship it as is, or write its own init on the same package.
//
// Kernel command line:
//
//	atom.roothash=<hex>   dm-verity root hash (ATOM_ROOT_HASH= is accepted too)
//	atom.live             live boot from raw root and hash partitions
//	init=<path>           init to run in the root
package main

import (
	"github.com/mirkobrombin/atomloops/boot"
)

func main() {
	boot.MountEarly()
	boot.LoadModules("virtio", "virtio_ring", "virtio_mmio", "virtio_pci_modern_dev", "virtio_pci_legacy_dev",
		"virtio_pci", "virtio_blk", "loop", "crc32c_generic", "libcrc32c", "reed_solomon", "dm-mod", "dm-bufio",
		"xxhash_generic", "dm-verity", "erofs", "overlay", "crc16", "mbcache", "jbd2", "ext4")
	cmd := boot.ReadCmdline()
	unlocked := boot.DeviceUnlocked(sintykey())

	hash := cmd.Value("atom.roothash")
	if hash == "" {
		hash = cmd.Value("ATOM_ROOT_HASH")
	}
	cfg := boot.Config{RootHash: hash, Live: cmd.Has("atom.live"), Unlocked: unlocked}
	ops := boot.SystemOps()
	var media boot.Media
	root, err := boot.SelectRoot(cfg, &media, ops)
	if err != nil {
		boot.Rescue(err.Error(), unlocked, "/bin/sh")
	}
	if unlocked {
		boot.Logf("DEVICE UNLOCKED - verified boot is OFF, this system is not sealed")
	}
	held, err := boot.ReleaseUnrelatedData(cfg, &media, root, ops)
	if err != nil {
		boot.Rescue(err.Error(), unlocked, "/bin/sh")
	}
	if _, err := boot.MountRoot(cfg, &media, root, held); err != nil {
		boot.Rescue(err.Error(), unlocked, "/bin/sh")
	}
	boot.MountESP(&media, root)
	init := boot.FindInit(cmd.Value("init"), "/sbin/init", "/usr/lib/systemd/systemd")
	if init == "" {
		boot.Rescue("no init found in root", unlocked, "/bin/sh")
	}
	boot.MountFirmware("/etc/atom-fw-root.pub")
	if err := boot.SwitchRoot(init, nil); err != nil {
		boot.Rescue("switch root: "+err.Error(), unlocked, "/bin/sh")
	}
}

func sintykey() string {
	for _, p := range []string{"/usr/bin/sintykey", "/sbin/sintykey", "/bin/sintykey"} {
		if boot.Executable(p) {
			return p
		}
	}
	return "sintykey"
}
