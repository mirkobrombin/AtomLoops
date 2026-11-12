package otad

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

// LiveIdentityPath records the root a live swap switched to. It lives on /run,
// so the next boot reads the identity from the signed command line again.
var LiveIdentityPath = "/run/atomloops/live/identity"

// LiveOffer tells whether the staged candidate may replace the running root
// without a reboot. Class is the release's apply class, opaque here: the
// system decides what it means and when to apply.
type LiveOffer struct {
	Class    string `json:"class,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason,omitempty"`
}

// LiveCandidate is the staged release with what a live swap needs to mount it.
type LiveCandidate struct {
	Offer    LiveOffer
	Image    string
	HashTree string
	RootHash string
	FromHash string
}

// LiveCandidateOf checks the staged candidate of walPath: its kept manifest must
// verify against rootPub, name the running release in live_from, target the
// running kernel, and the running root must be the installed one.
func LiveCandidateOf(walPath string, dirs StageDirs, rootPub []byte) (LiveCandidate, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return LiveCandidate{}, err
	}
	c := LiveCandidate{}
	if !d.HasPending() || d.RootFS.PendingHash == "" {
		c.Offer.Reason = "no staged update"
		return c, nil
	}
	c.Offer.To = d.RootFS.Pending
	m, _, err := keptManifest(dirs.Rootfs, d.RootFS.Pending, rootPub)
	if err != nil {
		c.Offer.Reason = err.Error()
		return c, nil
	}
	c.Offer.Class = m.ApplyClass()
	bi := bootedIdentity()
	c.Offer.From = bi.Version
	c.FromHash = bi.VerityHash
	switch {
	case bi.VerityHash == "" || bi.Version == "":
		c.Offer.Reason = "the running root has no signed identity"
	case bi.VerityHash == d.RootFS.PendingHash:
		c.Offer.Reason = "the staged update is already running"
	case !sameRelease(bi.Version, d.RootFS.Current) && !sameRelease(bi.Version, d.RootFS.LastKnownGood):
		c.Offer.Reason = fmt.Sprintf("the running release %s is not the installed one", bi.Version)
	case !m.LiveFrom(bi.Version):
		c.Offer.Reason = fmt.Sprintf("release %s cannot be applied live from %s", m.Version, bi.Version)
	case m.KernelRelease == "" || m.KernelRelease != RunningKernel():
		c.Offer.Reason = "the update does not run on the running kernel"
	case m.RootFSVerityHash != d.RootFS.PendingHash:
		c.Offer.Reason = "the kept manifest does not describe the staged root"
	default:
		c.Offer.Eligible = true
	}
	c.Image = filepath.Join(dirs.Rootfs, "rootfs-next.erofs")
	c.HashTree = filepath.Join(dirs.Rootfs, "rootfs-next.hash")
	c.RootHash = d.RootFS.PendingHash
	if c.Offer.Eligible && (!nonEmpty(c.Image) || !nonEmpty(c.HashTree)) {
		c.Offer.Eligible = false
		c.Offer.Reason = "the staged root is missing"
	}
	return c, nil
}

// WriteLiveIdentity records the root a live swap now runs.
func WriteLiveIdentity(version, rootHash string) error {
	if err := os.MkdirAll(filepath.Dir(LiveIdentityPath), 0o755); err != nil {
		return err
	}
	tmp := LiveIdentityPath + ".tmp"
	if err := os.WriteFile(tmp, []byte("ATOM_ROOT_HASH="+rootHash+" ATOM_VERSION="+version+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, LiveIdentityPath)
}

// CommitLive records the live swap to the staged candidate as a good boot of
// it, exactly as BootSuccess would after a reboot: the candidate becomes current
// and, once it reaches the stable threshold, is promoted. Until then the next
// boot still tries it on the trial budget, so the previous root stays the
// fallback.
func CommitLive(walPath string, dirs StageDirs, store CounterStore) (string, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	if !d.HasPending() {
		return "", errors.New("no staged update to commit")
	}
	bi := bootedIdentity()
	if bi.VerityHash != d.RootFS.PendingHash || !sameRelease(bi.Version, d.RootFS.Pending) {
		return "", fmt.Errorf("the running root %s is not the staged %s", bi.Version, d.RootFS.Pending)
	}
	cand := d.RootFS.Pending
	if d.RecordGoodBoot(true) {
		if err := PromoteSlots(dirs); err != nil {
			return "", fmt.Errorf("candidate %s slot promotion failed: %w", cand, err)
		}
		syscall.Sync()
		if dirs.ESP != "" {
			if err := WriteBootState(filepath.Join(dirs.ESP, "boot-state"), BootState{Target: "active"}); err != nil {
				return "", fmt.Errorf("candidate %s boot-state commit failed: %w", cand, err)
			}
		}
		syscall.Sync()
		if err := d.Save(walPath); err != nil {
			return "", err
		}
		CleanupNextSlots(dirs)
		syscall.Sync()
		if store != nil {
			if err := store.Advance(uint64(d.AntiRollback.CounterValue)); err != nil {
				return "", fmt.Errorf("promoted %s but arming anti-rollback counter failed: %w", cand, err)
			}
		}
		return fmt.Sprintf("%s applied live and promoted", cand), nil
	}
	if err := writeDeploymentBootState(d, dirs); err != nil {
		return "", err
	}
	syscall.Sync()
	if err := d.Save(walPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s applied live (%d/%d stable)", cand, d.Kernelcache.StableBoots, d.Kernelcache.StableThreshold), nil
}
