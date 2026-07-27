package otad

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Manifest describes an available update: the artifacts to fetch and the hashes
// to verify them against before anything is written to the device. Fields align
// with the PoC daemon (scripts/deploy/ota-daemon-mock.go) plus the doc's
// min_version anti-rollback floor.
//
// NOTE for B: confirm the field set against package.sh. rootfs_hash /
// kernelcache_hash here are the SHA256 of the whole downloaded artifact (the
// daemon's pre-install integrity check); the dm-verity root hash that the
// initramfs enforces at boot is separate and lives in the UKI cmdline, so it is
// not duplicated here.
type Manifest struct {
	Version    string `json:"version"`
	MinVersion string `json:"min_version"`
	RootFSURL  string `json:"rootfs_url"`
	RootFSHash string `json:"rootfs_hash"`
	// RootFSVerityHash is the candidate's dm-verity ROOT hash (distinct from RootFSHash, the
	// file SHA256). It equals the ATOM_ROOT_HASH baked into the candidate's signed UKI cmdline,
	// and lets the daemon confirm the candidate actually booted. Optional for back-compat.
	RootFSVerityHash string `json:"rootfs_verity_hash,omitempty"`
	KernelcacheURL   string `json:"kernelcache_url"`
	KernelcacheHash  string `json:"kernelcache_hash"`
	// KernelRelease is the kernel version (uname -r) the kernelcache is built for,
	// e.g. "7.1.3". It lets the daemon couple a kernel change with the matching
	// kernel-bound driver add-on bundles (see CoupledKernelCheck) so a kernel update
	// never strands a GPU driver. Empty means no coupling (firmware-only or legacy).
	KernelRelease string `json:"kernel_release,omitempty"`

	// Firmware is an optional, independent OTA track: a signed firmware add-on
	// image with its own version and anti-rollback floor, separate from rootfs
	// and kernelcache so it can be updated on its own cadence. All fields absent
	// means the update carries no firmware change. FirmwareHash is the file
	// SHA256 (pre-install integrity); FirmwareVerityHash is the image's dm-verity
	// root hash, enforced when the boot chain mounts it.
	FirmwareURL        string `json:"firmware_url,omitempty"`
	FirmwareHash       string `json:"firmware_hash,omitempty"`
	FirmwareVerityHash string `json:"firmware_verity_hash,omitempty"`
	FirmwareVersion    int    `json:"firmware_version,omitempty"`
	FirmwareMinVersion int    `json:"firmware_min_version,omitempty"`
	// FirmwareHashTreeURL points at the dm-verity hash tree for the image, the
	// sidecar veritysetup needs alongside the data device. FirmwareHashTreeHash is
	// its SHA256. Required when a firmware track carries a verity root hash.
	FirmwareHashTreeURL  string `json:"firmware_hashtree_url,omitempty"`
	FirmwareHashTreeHash string `json:"firmware_hashtree_hash,omitempty"`

	// FirmwareBundles is the multi-bundle firmware track: independently-versioned,
	// separately-selected add-on bundles (e.g. "intel-wifi-modern", "amdgpu"), each
	// unioned read-only over the base firmware. When present it supersedes the single
	// Firmware* fields above (kept for back-compat and folded in as a "default" bundle
	// by FirmwareBundleList).
	FirmwareBundles []FirmwareBundleSpec `json:"firmware_bundles,omitempty"`
}

// FirmwareBundleSpec describes one firmware add-on bundle in a manifest. Chips lists
// the drivers/devices it covers (for installer/recovery hardware selection); KernelMin
// and KernelMax bound the kernel range it is declared compatible with.
type FirmwareBundleSpec struct {
	Name         string   `json:"name"`
	URL          string   `json:"url"`
	Hash         string   `json:"hash"`
	VerityHash   string   `json:"verity_hash,omitempty"`
	HashTreeURL  string   `json:"hashtree_url,omitempty"`
	HashTreeHash string   `json:"hashtree_hash,omitempty"`
	Version      int      `json:"version"`
	MinVersion   int      `json:"min_version,omitempty"`
	Chips        []string `json:"chips,omitempty"`
	KernelMin    string   `json:"kernel_min,omitempty"`
	KernelMax    string   `json:"kernel_max,omitempty"`
	// CriticalDevices lists device-presence checks the early device-probe must pass for
	// this bundle to count as bound (e.g. "net:wlan0", "drm:/dev/dri/card0"). Empty means
	// the bundle is non-critical: a clean overlay mount with no firmware-load failure is
	// enough to confirm it. Critical survival firmware (wifi+display) lives in the base,
	// so most add-on bundles leave this empty.
	CriticalDevices []string `json:"critical_devices,omitempty"`
}

// FirmwareBundleList normalizes the firmware track to a bundle list: the explicit
// FirmwareBundles when present, otherwise the legacy single Firmware* fields folded
// into one bundle named "default", otherwise nil.
func (m Manifest) FirmwareBundleList() []FirmwareBundleSpec {
	if len(m.FirmwareBundles) > 0 {
		return m.FirmwareBundles
	}
	if m.FirmwareURL != "" {
		return []FirmwareBundleSpec{{
			Name: "default", URL: m.FirmwareURL, Hash: m.FirmwareHash,
			VerityHash: m.FirmwareVerityHash, HashTreeURL: m.FirmwareHashTreeURL,
			HashTreeHash: m.FirmwareHashTreeHash, Version: m.FirmwareVersion, MinVersion: m.FirmwareMinVersion,
		}}
	}
	return nil
}

// HasFirmware reports whether the manifest carries a firmware track (any bundle).
func (m Manifest) HasFirmware() bool { return len(m.FirmwareBundleList()) > 0 }

// ParseManifest decodes and validates a manifest. A manifest missing a version
// or any artifact reference is rejected, so staging never runs on a half-formed
// update description.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, err
	}
	switch {
	case m.Version == "":
		return Manifest{}, fmt.Errorf("manifest: missing version")
	case m.RootFSURL == "" || m.RootFSHash == "":
		return Manifest{}, fmt.Errorf("manifest: missing rootfs url/hash")
	case m.KernelcacheURL == "" || m.KernelcacheHash == "":
		return Manifest{}, fmt.Errorf("manifest: missing kernelcache url/hash")
	}
	// Firmware track (optional): validate every bundle, so staging never runs on a
	// half-formed one. Names must be unique (they are the on-disk slot directories).
	seen := map[string]bool{}
	for _, fw := range m.FirmwareBundleList() {
		switch {
		case fw.Name == "":
			return Manifest{}, fmt.Errorf("manifest: firmware bundle without a name")
		case seen[fw.Name]:
			return Manifest{}, fmt.Errorf("manifest: duplicate firmware bundle %q", fw.Name)
		case fw.URL == "" || fw.Hash == "":
			return Manifest{}, fmt.Errorf("manifest: firmware bundle %q url without hash", fw.Name)
		case fw.VerityHash != "" && (fw.HashTreeURL == "" || fw.HashTreeHash == ""):
			// A verity-enforced bundle needs its hash tree delivered too, or the
			// initramfs could never open dm-verity and the add-on would silently never load.
			return Manifest{}, fmt.Errorf("manifest: firmware bundle %q verity hash without a hash-tree url/hash", fw.Name)
		}
		seen[fw.Name] = true
	}
	return m, nil
}

// VerifySHA256 streams the file at path and checks its SHA256 against wantHex
// (case-insensitive hex). It reads in chunks so a multi-hundred-MB rootfs never
// has to fit in memory. A mismatch or a short/oversized file is an error, so a
// corrupt or truncated download can never be staged.
func VerifySHA256(path, wantHex string) error {
	want, err := hex.DecodeString(wantHex)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("verify: bad expected hash %q", wantHex)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := h.Sum(nil)
	if !hashEqual(got, want) {
		return fmt.Errorf("verify: %s sha256 mismatch: got %x want %s", path, got, wantHex)
	}
	return nil
}

// hashEqual is a length-safe constant-time-ish compare (hashes are public, so
// timing is not sensitive; this just avoids a bytes import).
func hashEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
