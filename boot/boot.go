// Package boot is the early-boot engine of Atom Loops: the steps an
// initramfs takes to find the root image whose dm-verity tree matches the
// signed root hash, mount it with the persistent /var of an installed system
// or the tmpfs of a live one, union the verified firmware bundles and hand
// over to the real init.
//
// It is the part of Atom Loops that enforces its boot contract, so a
// distribution's own init builds on it rather than reimplementing it. The
// reference init is cmd/atom-init. Loop devices and dm-verity are set up
// through the kernel interfaces directly; no shell or helper binaries are
// needed in the initramfs.
package boot
