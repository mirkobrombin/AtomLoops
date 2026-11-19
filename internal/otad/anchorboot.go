package otad

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

// BootIdentityPath records the root an anchor boot selected. A device whose boot
// image cannot follow an update boots with sing.roothash=anchor, so the command
// line names no root hash for the booted identity check to read.
var BootIdentityPath = "/run/atomloops/boot-identity"

// AnchorChoice is the root an anchor boot runs: the verified manifest of the chosen
// release, and whether it is a candidate on trial.
type AnchorChoice struct {
	Manifest Manifest
	Trial    bool
}

// ChooseAnchorRoot plays the loader's part on a device without one. It reads the
// boot-state and the WAL the daemon keeps beside the slots and picks the candidate
// while its trial budget lasts, the installed release otherwise. The root hash comes
// from that release's signed manifest kept under rootfs/release, verified offline
// against rootPub, so a tampered or missing anchor never yields a root. A candidate
// whose anchor does not verify falls back to the installed release.
func ChooseAnchorRoot(walPath, rootfs, esp string, rootPub []byte) (AnchorChoice, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return AnchorChoice{}, err
	}
	bs, _ := ReadBootState(filepath.Join(esp, "boot-state"))
	if d.HasPending() && bs.Target == "next" && bs.Trial && bs.Attempts > 0 {
		m, _, err := keptManifest(rootfs, d.RootFS.Pending, rootPub)
		if err == nil && m.RootFSVerityHash != "" {
			return AnchorChoice{Manifest: m, Trial: true}, nil
		}
	}
	if d.RootFS.Current == "" {
		return AnchorChoice{}, errors.New("anchor boot: no installed release recorded")
	}
	m, _, err := keptManifest(rootfs, d.RootFS.Current, rootPub)
	if err != nil {
		return AnchorChoice{}, err
	}
	if m.RootFSVerityHash == "" {
		return AnchorChoice{}, fmt.Errorf("anchor boot: release %s carries no rootfs verity hash", m.Version)
	}
	return AnchorChoice{Manifest: m}, nil
}

// SpendAnchorTrial takes one attempt off the candidate's trial budget, as the
// loader does before it boots a candidate.
func SpendAnchorTrial(esp string) error {
	path := filepath.Join(esp, "boot-state")
	bs, err := ReadBootState(path)
	if err != nil {
		return err
	}
	if !bs.Trial || bs.Attempts <= 0 {
		return nil
	}
	bs.Attempts--
	return WriteBootState(path, bs)
}

// WriteBootIdentity records the root hash and version an anchor boot selected.
func WriteBootIdentity(verityHash, version string) error {
	if verityHash == "" {
		return errors.New("boot identity: no root hash")
	}
	if err := os.MkdirAll(filepath.Dir(BootIdentityPath), 0o755); err != nil {
		return err
	}
	tmp := BootIdentityPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("ATOM_ROOT_HASH=%s ATOM_VERSION=%s\n", verityHash, version)), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, BootIdentityPath)
}
