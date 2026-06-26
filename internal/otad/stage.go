package otad

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

// StageDirs is where staged artifacts land. rootfs images go on the /boot/rootfs
// partition; the kernelcache UKI goes on the ESP under EFI/atom. The image build
// owns the exact paths; the daemon just writes the -next slot.
type StageDirs struct {
	Rootfs string // e.g. /boot/rootfs
	ESP    string // e.g. /boot/efi/EFI/atom
}

// Stage performs the full M2 update: fetch + verify the signed manifest, fetch +
// verify (SHA256) the rootfs and kernelcache artifacts into their -next slots, and
// mark the candidate pending in the WAL so the next boot tries it. Nothing is
// committed to the WAL unless every artifact is downloaded and verified, so a
// partial or tampered update never becomes bootable.
//
// This is the service tier end to end: go-foundation httpx does the retrying
// downloads, stdlib ed25519/sha256 do the trust checks, and the deployment WAL
// (shared with the initramfs) records the transition.
func Stage(ctx context.Context, walPath, manifestURL string, pubkey []byte, dirs StageDirs) (string, error) {
	work, err := os.MkdirTemp("", "atomd-stage-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)

	// 1. Manifest + its detached signature.
	mPath := filepath.Join(work, "manifest.json")
	if _, err := FetchTo(ctx, manifestURL, mPath); err != nil {
		return "", err
	}
	sPath := filepath.Join(work, "manifest.json.sig")
	if _, err := FetchTo(ctx, manifestURL+".sig", sPath); err != nil {
		return "", err
	}
	mData, err := os.ReadFile(mPath)
	if err != nil {
		return "", err
	}
	sData, err := os.ReadFile(sPath)
	if err != nil {
		return "", err
	}
	if !VerifyManifestSig(mData, sData, pubkey) {
		return "", fmt.Errorf("stage: manifest signature invalid -- refusing update")
	}
	m, err := ParseManifest(mData)
	if err != nil {
		return "", err
	}

	// 2. rootfs -> /boot/rootfs/rootfs-next.erofs, verified.
	if err := os.MkdirAll(dirs.Rootfs, 0o755); err != nil {
		return "", err
	}
	rPath := filepath.Join(dirs.Rootfs, "rootfs-next.erofs")
	if _, err := FetchTo(ctx, m.RootFSURL, rPath); err != nil {
		return "", err
	}
	if err := VerifySHA256(rPath, m.RootFSHash); err != nil {
		os.Remove(rPath)
		return "", err
	}

	// 3. kernelcache -> ESP/kernelcache-next.efi, verified.
	if err := os.MkdirAll(dirs.ESP, 0o755); err != nil {
		return "", err
	}
	kPath := filepath.Join(dirs.ESP, "kernelcache-next.efi")
	if _, err := FetchTo(ctx, m.KernelcacheURL, kPath); err != nil {
		return "", err
	}
	if err := VerifySHA256(kPath, m.KernelcacheHash); err != nil {
		os.Remove(kPath)
		return "", err
	}

	// 4. Only now, everything verified on disk: mark the candidate pending.
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	d.Deploy(m.Version)
	if err := d.Save(walPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("staged %s (rootfs + kernelcache fetched + verified); reboot to try it", m.Version), nil
}
