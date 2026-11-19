package otad

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mirkobrombin/atomloops/internal/hooks"
)

// KernelHookDir holds the hooks of a device whose bootloader cannot read the
// kernelcache from the ESP, such as a phone that boots from its own boot
// partitions. Each executable is run with the phase as its only argument and
// installs the kernelcache it is given where the bootloader finds it:
//
//	staged  a candidate is fully verified on disk; install its kernelcache so
//	        the next boot runs the candidate's kernel. A failure refuses the
//	        candidate.
//	booted  the device booted the release in ATOM_VERSION; install its
//	        kernelcache if another one is in place, as after a candidate that
//	        failed its trial, and restart the device to run it.
//
// ATOM_KERNELCACHE is the verified kernelcache, ATOM_KERNELCACHE_HASH its
// SHA256 from the signed manifest, ATOM_VERSION the release it belongs to.
var KernelHookDir = "/usr/lib/atomloops/kernel.d"

func runKernelHooks(phase, kernelcache, hash, version string) error {
	return hooks.Run("kernel", KernelHookDir, phase, []string{
		"ATOM_KERNEL_PHASE=" + phase,
		"ATOM_KERNELCACHE=" + kernelcache,
		"ATOM_KERNELCACHE_HASH=" + hash,
		"ATOM_VERSION=" + version,
	})
}

// kernelcacheSlots are the kernelcache files a booted release may run from.
var kernelcacheSlots = []string{"kernelcache-active.efi", "kernelcache-next.efi", "kernelcache-prev.efi"}

// SyncBootedKernel runs the booted kernel hooks for the release an anchor boot
// selected, with the kernelcache its signed manifest names. A device that boots
// through a loader records no boot identity and runs nothing.
func SyncBootedKernel(rootfs, esp string, rootPub []byte) error {
	version, err := bootedVersion()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	m, _, err := keptManifest(rootfs, version, rootPub)
	if err != nil {
		return err
	}
	for _, name := range kernelcacheSlots {
		path := filepath.Join(esp, name)
		if VerifySHA256(path, m.KernelcacheHash) == nil {
			return runKernelHooks("booted", path, m.KernelcacheHash, version)
		}
	}
	return fmt.Errorf("no kernelcache kept here matches release %s", version)
}

func bootedVersion() (string, error) {
	b, err := os.ReadFile(BootIdentityPath)
	if err != nil {
		return "", err
	}
	for _, f := range strings.Fields(string(b)) {
		if v, ok := strings.CutPrefix(f, "ATOM_VERSION="); ok && v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("%s names no version", BootIdentityPath)
}
