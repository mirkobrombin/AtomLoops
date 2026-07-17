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
	Version         string `json:"version"`
	MinVersion      string `json:"min_version"`
	RootFSURL       string `json:"rootfs_url"`
	RootFSHash      string `json:"rootfs_hash"`
	// RootFSVerityHash is the candidate's dm-verity ROOT hash (distinct from RootFSHash, the
	// file SHA256). It equals the ATOM_ROOT_HASH baked into the candidate's signed UKI cmdline,
	// and lets the daemon confirm the candidate actually booted. Optional for back-compat.
	RootFSVerityHash string `json:"rootfs_verity_hash,omitempty"`
	KernelcacheURL  string `json:"kernelcache_url"`
	KernelcacheHash string `json:"kernelcache_hash"`
}

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
