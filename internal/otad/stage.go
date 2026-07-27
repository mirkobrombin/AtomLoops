package otad

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

// StageDirs is where staged artifacts land. rootfs images go on the /boot/rootfs
// partition; the kernelcache UKI goes on the ESP under EFI/atom. The image build
// owns the exact paths; the daemon just writes the -next slot.
type StageDirs struct {
	Rootfs   string // e.g. /boot/rootfs
	ESP      string // e.g. /boot/efi/EFI/atom
	Firmware string // e.g. /boot/firmware (empty when no firmware track is staged)
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
// rootPub is the embedded ROOT public key. revocationURL is the root-signed
// revocation list (empty to skip). The manifest is verified against the SIGNING
// key vouched for by a root-signed cert fetched next to the manifest, and the
// revocation list is checked FIRST, per the A4.1 trust chain.
func Stage(ctx context.Context, walPath, manifestURL, revocationURL string, rootPub []byte, dirs StageDirs) (string, error) {
	work, err := os.MkdirTemp("", "atomd-stage-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)

	fetch := func(url, name string) ([]byte, error) {
		p := filepath.Join(work, name)
		if _, err := FetchTo(ctx, url, p); err != nil {
			return nil, err
		}
		return os.ReadFile(p)
	}

	// 1. Manifest + its detached signature.
	mData, err := fetch(manifestURL, "manifest.json")
	if err != nil {
		return "", err
	}
	mSig, err := fetch(manifestURL+".sig", "manifest.json.sig")
	if err != nil {
		return "", err
	}

	// 2. Signing cert (sibling of the manifest), verified against the ROOT key.
	certURL := manifestURL[:strings.LastIndex(manifestURL, "/")+1] + "signing-cert.json"
	certData, err := fetch(certURL, "signing-cert.json")
	if err != nil {
		return "", fmt.Errorf("stage: fetch signing cert: %w", err)
	}
	certSig, err := fetch(certURL+".sig", "signing-cert.json.sig")
	if err != nil {
		return "", err
	}
	signingPub, certVer, err := trust.VerifyCert(certData, certSig, rootPub, time.Now())
	if err != nil {
		return "", fmt.Errorf("stage: %w", err)
	}

	// 3. Revocation FIRST: refuse a revoked/too-old signing cert before trusting it.
	if revocationURL != "" {
		revData, err := fetch(revocationURL, "revocation.json")
		if err != nil {
			return "", fmt.Errorf("stage: fetch revocation: %w", err)
		}
		revSig, err := fetch(revocationURL+".sig", "revocation.json.sig")
		if err != nil {
			return "", err
		}
		if err := trust.CheckRevocation(revData, revSig, rootPub, certVer); err != nil {
			return "", fmt.Errorf("stage: %w", err)
		}
	}

	// 4. Manifest signature vs the (root-vouched) signing key.
	if !trust.Verify(mData, mSig, signingPub) {
		return "", fmt.Errorf("stage: manifest signature invalid -- refusing update")
	}
	m, err := ParseManifest(mData)
	if err != nil {
		return "", err
	}

	// Software anti-rollback (A4.2, level L1): refuse to stage a manifest whose
	// version is a downgrade below the currently installed one. At the hardware
	// levels (L4/L5) the monotonic counter enforces this at boot; here we refuse
	// to even stage a downgrade, so a rolled-back signing key cannot push an old,
	// vulnerable image.
	cur, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	if isDowngrade(m.Version, cur.RootFS.Current) {
		return "", fmt.Errorf("stage: %s is below installed %s -- refused (anti-rollback)", m.Version, cur.RootFS.Current)
	}

	// Atomic kernel<->driver coupling: refuse a kernel-changing update that would
	// leave a detected GPU without its matching kernel-bound driver bundle, so we
	// never boot a new kernel with a dead proprietary driver.
	if err := m.CoupledKernelCheck(DetectGPUChips("")); err != nil {
		return "", fmt.Errorf("stage: %w", err)
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

	// 2b. the rootfs hash tree, beside the image it measures. Without it the promoted
	// image would be checked against the previous tree and fail dm-verity, so a
	// candidate that does not carry one is refused here rather than at the next boot.
	if m.RootFSHashTreeURL == "" {
		os.Remove(rPath)
		return "", fmt.Errorf("stage: manifest carries no rootfs hash tree -- refusing (candidate would not boot)")
	}
	rhPath := filepath.Join(dirs.Rootfs, "rootfs-next.hash")
	if _, err := FetchTo(ctx, m.RootFSHashTreeURL, rhPath); err != nil {
		os.Remove(rPath)
		return "", err
	}
	if err := VerifySHA256(rhPath, m.RootFSHashTreeHash); err != nil {
		os.Remove(rPath)
		os.Remove(rhPath)
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

	// 3b. its loader signature. The loader verifies the UKI before chaining it, so a
	// kernelcache promoted next to the previous signature halts the boot.
	if m.KernelcacheSigURL == "" {
		os.Remove(kPath)
		return "", fmt.Errorf("stage: manifest carries no kernelcache signature -- refusing (loader would not chain it)")
	}
	kSigPath := filepath.Join(dirs.ESP, "kernelcache-next.efi.sig")
	if _, err := FetchTo(ctx, m.KernelcacheSigURL, kSigPath); err != nil {
		os.Remove(kPath)
		return "", err
	}
	if err := VerifySHA256(kSigPath, m.KernelcacheSigHash); err != nil {
		os.Remove(kPath)
		os.Remove(kSigPath)
		return "", err
	}

	// 3b. firmware (optional, independent track): each add-on bundle -> its own slot dir
	// /boot/firmware/<name>/firmware-next.img (+ hash tree + a per-bundle copy of the
	// release-signed anchor the initramfs re-verifies offline). Skipped when the manifest
	// carries no firmware bundle.
	bundles := m.FirmwareBundleList()
	if len(bundles) > 0 && dirs.Firmware == "" {
		return "", fmt.Errorf("stage: manifest has a firmware track but no firmware dir configured")
	}
	// Fetch-on-detect: stage only the bundles this machine actually needs, so an NVIDIA
	// driver bundle is never downloaded on an AMD/Intel box, and a kernel-bound bundle is
	// fetched only for the kernel it was built against. A bundle with no Chips and no
	// kernel bound (survival/default firmware) matches everything.
	chips := DetectGPUChips("")
	// Match driver bundles against the kernel this update TARGETS (the pending
	// kernelcache), not the running one, so a kernel-changing update fetches the
	// bundle built for the NEW kernel. Firmware-only updates leave KernelRelease
	// empty and fall back to the running kernel.
	kernel := m.KernelRelease
	if kernel == "" {
		kernel = RunningKernel()
	}
	// staged holds only the bundles this machine actually fetched (matched its
	// hardware and target kernel). The deploy, promote, and summary steps below run
	// over staged, never the full list, so a bundle skipped here is never marked
	// deployed or activated (which would promote a slot that was never written).
	staged := make([]FirmwareBundleSpec, 0, len(bundles))
	for _, fw := range bundles {
		if !fw.MatchesHardware(chips, kernel) {
			continue
		}
		staged = append(staged, fw)
		bdir := filepath.Join(dirs.Firmware, fw.Name)
		if err := os.MkdirAll(bdir, 0o755); err != nil {
			return "", err
		}
		imgPath := filepath.Join(bdir, "firmware-next.img")
		if _, err := FetchTo(ctx, fw.URL, imgPath); err != nil {
			return "", err
		}
		if err := VerifySHA256(imgPath, fw.Hash); err != nil {
			os.Remove(imgPath)
			return "", err
		}
		// The dm-verity hash tree sidecar the initramfs feeds to veritysetup.
		if fw.VerityHash != "" {
			htPath := filepath.Join(bdir, "firmware-next.hash")
			if _, err := FetchTo(ctx, fw.HashTreeURL, htPath); err != nil {
				os.Remove(imgPath)
				return "", err
			}
			if err := VerifySHA256(htPath, fw.HashTreeHash); err != nil {
				os.Remove(imgPath)
				os.Remove(htPath)
				return "", err
			}
		}
		// Per-bundle copy of the boot trust anchor (the release-signed manifest chain
		// the initramfs re-verifies offline for this bundle's verity hash), so each
		// bundle can roll back independently to its own previous anchor.
		if err := WriteFirmwareAnchor(bdir, "next", mData, mSig, certData, certSig); err != nil {
			os.Remove(imgPath)
			return "", fmt.Errorf("stage: persist firmware anchor for %q: %w", fw.Name, err)
		}
	}

	// 4. Only now, everything verified on disk: mark the candidate pending.
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	d.Deploy(m.Version)
	d.RootFS.PendingHash = m.RootFSVerityHash // record the candidate's verity hash for the boot-check
	for _, fw := range staged {
		// Stage each bundle on its own track; its anti-rollback floor refuses a
		// downgrade independently of the rootfs version and of the other bundles.
		if !d.DeployFirmware(fw.Name, fw.Version, fw.VerityHash) {
			return "", fmt.Errorf("stage: firmware bundle %q v%d is below its anti-rollback floor -- refused", fw.Name, fw.Version)
		}
	}
	if err := d.Save(walPath); err != nil {
		return "", err
	}
	// Arm the ESP boot-state so the loader boots the -next slot on the trial budget.
	if err := SyncBootState(walPath, dirs); err != nil {
		return "", fmt.Errorf("staged %s but arming boot-state failed: %w", m.Version, err)
	}
	// Promote each firmware bundle slot next -> active so the next boot mounts it. The
	// prior image is kept as a backup for RollbackFirmwareSlot if it fails to probe; the
	// initramfs only ever mounts -active, so no trial-slot logic is needed early boot.
	for _, fw := range staged {
		if err := ActivateFirmwareSlot(filepath.Join(dirs.Firmware, fw.Name)); err != nil {
			return "", fmt.Errorf("staged %s but activating firmware bundle %q failed: %w", m.Version, fw.Name, err)
		}
	}
	artifacts := "rootfs + kernelcache fetched + verified"
	if len(staged) > 0 {
		names := make([]string, len(staged))
		for i, fw := range staged {
			names[i] = fmt.Sprintf("%s v%d", fw.Name, fw.Version)
		}
		artifacts = fmt.Sprintf("rootfs + kernelcache + firmware [%s] fetched + verified", strings.Join(names, ", "))
	}
	return fmt.Sprintf("staged %s (%s); reboot to try it", m.Version, artifacts), nil
}

// versionNum extracts the trailing integer of a version string (v43 -> 43).
func versionNum(v string) (int, bool) {
	i := len(v)
	for i > 0 && v[i-1] >= '0' && v[i-1] <= '9' {
		i--
	}
	if i == len(v) {
		return 0, false
	}
	n := 0
	for _, c := range v[i:] {
		n = n*10 + int(c-'0')
	}
	return n, true
}

// isDowngrade reports whether newV is numerically below curV. If either version
// lacks a numeric component the comparison declines (returns false) rather than
// blocking a legitimate non-numeric scheme.
func isDowngrade(newV, curV string) bool {
	n, ok1 := versionNum(newV)
	c, ok2 := versionNum(curV)
	if !ok1 || !ok2 {
		return false
	}
	return n < c
}
