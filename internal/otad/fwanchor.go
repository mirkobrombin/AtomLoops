package otad

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mirkobrombin/atomloops/internal/trust"
)

// The firmware boot trust anchor. The dm-verity root hash of an OTA-delivered
// firmware add-on cannot live in the signed UKI cmdline (that is fixed and signed
// at image-build time, so no OTA could update it without re-signing the UKI).
// Instead the anchor is the release-signed OTA manifest itself, persisted to the
// firmware partition next to the image: the initramfs re-verifies the same trust
// chain offline (root pubkey -> signing cert -> manifest) with a root public key
// baked into the signed initramfs, then reads FirmwareVerityHash from the verified
// manifest and opens dm-verity with it. No on-device signing key is needed and the
// firmware track stays independent of the kernelcache/UKI.
//
// Slots mirror the rootfs track: WriteFirmwareAnchor writes the "-next" set staged
// beside firmware-next.img; ActivateFirmwareAnchor renames it to "-active" (saving
// the prior active as a rollback backup) once the candidate has probed clean.

const (
	fwAnchorManifest = "fw-manifest"
	fwAnchorCert     = "fw-signing-cert"
)

func anchorPath(dir, base, slot, ext string) string {
	return filepath.Join(dir, fmt.Sprintf("%s-%s%s", base, slot, ext))
}

// WriteFirmwareAnchor persists the already-verified manifest and signing cert (with
// their detached signatures) into dir under the given slot ("next" or "active"), so
// the initramfs can re-verify them offline at boot. The four bytes arguments are the
// exact bytes fetched and verified during staging.
func WriteFirmwareAnchor(dir, slot string, manifest, manifestSig, cert, certSig []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := []struct {
		path string
		data []byte
	}{
		{anchorPath(dir, fwAnchorManifest, slot, ".json"), manifest},
		{anchorPath(dir, fwAnchorManifest, slot, ".json.sig"), manifestSig},
		{anchorPath(dir, fwAnchorCert, slot, ".json"), cert},
		{anchorPath(dir, fwAnchorCert, slot, ".json.sig"), certSig},
	}
	for _, f := range files {
		if err := os.WriteFile(f.path, f.data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// VerifyFirmwareAnchor re-verifies the persisted anchor offline exactly as staging
// did: the signing cert against the baked root public key, then the manifest against
// the cert's signing key, and returns the trusted dm-verity root hash for the named
// bundle. This is the boot-time gate: a missing, tampered or wrong-key anchor, or an
// anchor that does not vouch for the bundle, returns an error and the caller must fall
// open to the base survival firmware, never brick.
func VerifyFirmwareAnchor(dir, slot string, rootPub []byte, now time.Time, bundle string) (verityHash string, version int, err error) {
	fw, err := VerifiedFirmwareBundle(dir, slot, rootPub, now, bundle)
	if err != nil {
		return "", 0, err
	}
	return fw.VerityHash, fw.Version, nil
}

// VerifiedFirmwareBundle re-verifies the anchor offline (cert vs baked root pubkey,
// then manifest vs the cert's signing key) and returns the full, trusted spec for the
// named bundle -- verity hash plus its metadata (chips, critical devices, kernel range)
// the early device-probe reads. A missing, tampered or wrong-key anchor, or one that
// does not vouch for the bundle, is an error and the caller must fall open to base.
func VerifiedFirmwareBundle(dir, slot string, rootPub []byte, now time.Time, bundle string) (FirmwareBundleSpec, error) {
	read := func(base, ext string) ([]byte, error) {
		return os.ReadFile(anchorPath(dir, base, slot, ext))
	}
	certData, err := read(fwAnchorCert, ".json")
	if err != nil {
		return FirmwareBundleSpec{}, fmt.Errorf("firmware anchor: no signing cert: %w", err)
	}
	certSig, err := read(fwAnchorCert, ".json.sig")
	if err != nil {
		return FirmwareBundleSpec{}, fmt.Errorf("firmware anchor: no cert signature: %w", err)
	}
	signingPub, _, err := trust.VerifyCert(certData, certSig, rootPub, now)
	if err != nil {
		return FirmwareBundleSpec{}, fmt.Errorf("firmware anchor: %w", err)
	}
	mData, err := read(fwAnchorManifest, ".json")
	if err != nil {
		return FirmwareBundleSpec{}, fmt.Errorf("firmware anchor: no manifest: %w", err)
	}
	mSig, err := read(fwAnchorManifest, ".json.sig")
	if err != nil {
		return FirmwareBundleSpec{}, fmt.Errorf("firmware anchor: no manifest signature: %w", err)
	}
	if !trust.Verify(mData, mSig, signingPub) {
		return FirmwareBundleSpec{}, fmt.Errorf("firmware anchor: manifest signature invalid")
	}
	m, err := ParseManifest(mData)
	if err != nil {
		return FirmwareBundleSpec{}, err
	}
	for _, fw := range m.FirmwareBundleList() {
		if fw.Name == bundle {
			if fw.VerityHash == "" {
				return FirmwareBundleSpec{}, fmt.Errorf("firmware anchor: bundle %q carries no verity hash", bundle)
			}
			return fw, nil
		}
	}
	return FirmwareBundleSpec{}, fmt.Errorf("firmware anchor: manifest does not vouch for bundle %q", bundle)
}

// ActivateFirmwareAnchor promotes the "-next" anchor to "-active", preserving the
// current active set as "-active.bak" for rollback. It mirrors the firmware image
// activation and is atomic per-file (rename), so an interrupted activation leaves
// either the old or the new anchor complete, never a torn mix that fails to verify.
func ActivateFirmwareAnchor(dir string) error {
	for _, f := range []struct{ base, ext string }{
		{fwAnchorManifest, ".json"}, {fwAnchorManifest, ".json.sig"},
		{fwAnchorCert, ".json"}, {fwAnchorCert, ".json.sig"},
	} {
		next := anchorPath(dir, f.base, "next", f.ext)
		active := anchorPath(dir, f.base, "active", f.ext)
		if _, err := os.Stat(next); err != nil {
			return fmt.Errorf("activate firmware anchor: missing %s: %w", next, err)
		}
		if _, err := os.Stat(active); err == nil {
			os.Rename(active, active+".bak")
		}
		if err := os.Rename(next, active); err != nil {
			return err
		}
	}
	return nil
}

// RollbackFirmwareAnchor restores the "-active.bak" set over "-active" after a failed
// firmware candidate, so the boot anchor matches the rolled-back firmware image.
func RollbackFirmwareAnchor(dir string) error {
	for _, f := range []struct{ base, ext string }{
		{fwAnchorManifest, ".json"}, {fwAnchorManifest, ".json.sig"},
		{fwAnchorCert, ".json"}, {fwAnchorCert, ".json.sig"},
	} {
		active := anchorPath(dir, f.base, "active", f.ext)
		bak := active + ".bak"
		if _, err := os.Stat(bak); err != nil {
			continue // no backup: nothing to restore for this file
		}
		if err := os.Rename(bak, active); err != nil {
			return err
		}
	}
	return nil
}

// The firmware image slot names the initramfs mounts. firmware-active.img is the one
// booted; -next is the staged candidate; -active.bak the previous image kept for
// rollback. The .hash sidecar is the dm-verity hash tree fed to veritysetup.
var fwImageFiles = []string{"firmware.img", "firmware.hash"}

func imagePath(dir, slot, name string) string {
	// name is "firmware.img" -> "firmware-<slot>.img".
	dot := len(name)
	for i := range name {
		if name[i] == '.' {
			dot = i
			break
		}
	}
	return filepath.Join(dir, name[:dot]+"-"+slot+name[dot:])
}

// ActivateFirmwareSlot promotes the staged firmware (image, hash and trust anchor)
// from -next to -active, saving the prior active as -active.bak / .bak for rollback.
// The anchor is promoted last: if activation is interrupted mid-way the boot sees a
// new image with a stale or missing anchor, the verity hash will not match, and the
// initramfs falls open to the base survival firmware -- never a brick.
func ActivateFirmwareSlot(dir string) error {
	for i, name := range fwImageFiles {
		next := imagePath(dir, "next", name)
		active := imagePath(dir, "active", name)
		if _, err := os.Stat(next); err != nil {
			// The image (first entry) is mandatory; the hash tree is only present
			// when the firmware is verity-enforced, so a missing one is skipped.
			if i == 0 {
				return fmt.Errorf("activate firmware slot: missing %s: %w", next, err)
			}
			continue
		}
		if _, err := os.Stat(active); err == nil {
			os.Rename(active, active+".bak")
		}
		if err := os.Rename(next, active); err != nil {
			return err
		}
	}
	return ActivateFirmwareAnchor(dir)
}

// RollbackFirmwareSlot restores the previous firmware image and anchor from their
// backups after a candidate fails to probe clean, matching deployment.RollbackFirmware
// on the WAL side.
func RollbackFirmwareSlot(dir string) error {
	if err := RollbackFirmwareAnchor(dir); err != nil {
		return err
	}
	for _, name := range fwImageFiles {
		active := imagePath(dir, "active", name)
		bak := active + ".bak"
		if _, err := os.Stat(bak); err != nil {
			continue
		}
		if err := os.Rename(bak, active); err != nil {
			return err
		}
	}
	return nil
}

// FinalizeFirmwareSlot drops the rollback backups once a firmware candidate has
// probed clean and been promoted: after this there is no going back to the prior
// firmware, so the .bak image, hash and anchor files are removed.
func FinalizeFirmwareSlot(dir string) error {
	for _, name := range fwImageFiles {
		os.Remove(imagePath(dir, "active", name) + ".bak")
	}
	for _, f := range []struct{ base, ext string }{
		{fwAnchorManifest, ".json"}, {fwAnchorManifest, ".json.sig"},
		{fwAnchorCert, ".json"}, {fwAnchorCert, ".json.sig"},
	} {
		os.Remove(anchorPath(dir, f.base, "active", f.ext) + ".bak")
	}
	return nil
}
