package otad

import (
	"path/filepath"
	"syscall"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func promoteRunningCandidate(walPath string, dirs StageDirs) (bool, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return false, err
	}
	if !d.HasPending() || d.Kernelcache.StableBoots < 1 {
		return false, nil
	}
	bi := bootedIdentity()
	if bi.VerityHash == "" || d.RootFS.PendingHash == "" || bi.VerityHash != d.RootFS.PendingHash ||
		bi.Version == "" || !sameRelease(bi.Version, d.RootFS.Pending) {
		return false, nil
	}
	d.PromoteRunning()
	if err := PromoteSlots(dirs); err != nil {
		return false, err
	}
	syscall.Sync()
	if dirs.ESP != "" {
		if err := WriteBootState(filepath.Join(dirs.ESP, "boot-state"), BootState{Target: "active"}); err != nil {
			return false, err
		}
	}
	syscall.Sync()
	if err := d.Save(walPath); err != nil {
		return false, err
	}
	CleanupNextSlots(dirs)
	syscall.Sync()
	return true, nil
}
