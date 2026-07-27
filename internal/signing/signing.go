// Package signing is the release-side counterpart to the daemon's trust checks:
// it produces the Ed25519 keypair and the detached manifest signatures that
// otad.Stage (and the loader) verify. Kept separate from the device code because
// this runs where updates are built, not on the device.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

// IssueCert generates a signing keypair and writes it + a root-signed cert
// (signing-cert-vN.json + .sig). The signed bytes are exactly the written bytes.
func IssueCert(rootPrivPath, certPath, signingKeyPath string, version int, validity time.Duration, now time.Time) error {
	root, err := os.ReadFile(rootPrivPath)
	if err != nil {
		return err
	}
	if len(root) != ed25519.PrivateKeySize {
		return fmt.Errorf("issue-cert: root key must be %d bytes, got %d", ed25519.PrivateKeySize, len(root))
	}
	spub, spriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	cert := trust.SigningCert{
		Version:       version,
		SigningPubkey: base64.StdEncoding.EncodeToString(spub),
		IssuedAt:      now.UTC().Format(time.RFC3339),
		NotAfter:      now.Add(validity).UTC().Format(time.RFC3339),
	}
	certBytes, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(root), certBytes)
	if err := os.WriteFile(certPath, certBytes, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(certPath+".sig", sig, 0o644); err != nil {
		return err
	}
	return os.WriteFile(signingKeyPath, spriv, 0o600)
}

// Revoke writes a root-signed revocation list (+ .sig).
func Revoke(rootPrivPath, outPath string, minVersion int, revoked []int, now time.Time) error {
	root, err := os.ReadFile(rootPrivPath)
	if err != nil {
		return err
	}
	if len(root) != ed25519.PrivateKeySize {
		return fmt.Errorf("revoke: root key must be %d bytes, got %d", ed25519.PrivateKeySize, len(root))
	}
	if revoked == nil {
		revoked = []int{}
	}
	rev := trust.Revocation{MinCertVersion: minVersion, Revoked: revoked, UpdatedAt: now.UTC().Format(time.RFC3339)}
	b, err := json.Marshal(rev)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(root), b)
	if err := os.WriteFile(outPath, b, 0o644); err != nil {
		return err
	}
	return os.WriteFile(outPath+".sig", sig, 0o644)
}

// hashFile streams a file and returns its SHA256 as lowercase hex.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// BuildManifest computes the SHA256 of the rootfs and kernelcache artifacts and
// writes a manifest.json (indented) describing the update. minVersion is the
// anti-rollback floor the update declares. Returns the path written. Sign the
// result with SignManifest before publishing.
// FirmwareSpec describes one firmware add-on bundle to fold into a manifest.
// ImageFile/HashTreeFile are hashed locally for the pre-install integrity checks;
// VerityHash is the dm-verity root hash veritysetup printed when the image was built.
// Name identifies the bundle (e.g. "intel-wifi-modern"); Chips/KernelMin/KernelMax
// carry hardware-selection and kernel-compatibility metadata.
type FirmwareSpec struct {
	Name                      string
	Version, MinVersion       int
	ImageFile, ImageURL       string
	VerityHash                string
	HashTreeFile, HashTreeURL string
	Chips                     []string
	KernelMin, KernelMax      string
	CriticalDevices           []string
}

func BuildManifest(outPath, version, minVersion, rootfsFile, rootfsURL, kcFile, kcURL string, fw ...FirmwareSpec) (string, error) {
	rh, err := hashFile(rootfsFile)
	if err != nil {
		return "", fmt.Errorf("hash rootfs: %w", err)
	}
	kh, err := hashFile(kcFile)
	if err != nil {
		return "", fmt.Errorf("hash kernelcache: %w", err)
	}
	m := otad.Manifest{
		Version:         version,
		MinVersion:      minVersion,
		RootFSURL:       rootfsURL,
		RootFSHash:      rh,
		KernelcacheURL:  kcURL,
		KernelcacheHash: kh,
	}
	// A single unnamed bundle uses the legacy single-firmware fields (back-compat);
	// any named or multiple bundles use the firmware_bundles array.
	if len(fw) == 1 && fw[0].Name == "" {
		f := fw[0]
		fih, err := hashFile(f.ImageFile)
		if err != nil {
			return "", fmt.Errorf("hash firmware image: %w", err)
		}
		fhh, err := hashFile(f.HashTreeFile)
		if err != nil {
			return "", fmt.Errorf("hash firmware hash tree: %w", err)
		}
		m.FirmwareURL = f.ImageURL
		m.FirmwareHash = fih
		m.FirmwareVerityHash = f.VerityHash
		m.FirmwareHashTreeURL = f.HashTreeURL
		m.FirmwareHashTreeHash = fhh
		m.FirmwareVersion = f.Version
		m.FirmwareMinVersion = f.MinVersion
	} else {
		for _, f := range fw {
			fih, err := hashFile(f.ImageFile)
			if err != nil {
				return "", fmt.Errorf("hash firmware bundle %q image: %w", f.Name, err)
			}
			fhh, err := hashFile(f.HashTreeFile)
			if err != nil {
				return "", fmt.Errorf("hash firmware bundle %q hash tree: %w", f.Name, err)
			}
			m.FirmwareBundles = append(m.FirmwareBundles, otad.FirmwareBundleSpec{
				Name: f.Name, URL: f.ImageURL, Hash: fih,
				VerityHash: f.VerityHash, HashTreeURL: f.HashTreeURL, HashTreeHash: fhh,
				Version: f.Version, MinVersion: f.MinVersion,
				Chips: f.Chips, KernelMin: f.KernelMin, KernelMax: f.KernelMax,
				CriticalDevices: f.CriticalDevices,
			})
		}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(outPath, b, 0o644); err != nil {
		return "", err
	}
	return outPath, nil
}

// GenerateKeyFiles writes a fresh Ed25519 keypair: privPath gets the 64-byte
// private key (mode 0600), pubPath gets the 32-byte public key, which is the raw
// form the daemon (--pubkey) and the loader read.
func GenerateKeyFiles(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(privPath, priv, 0o600); err != nil {
		return err
	}
	return os.WriteFile(pubPath, pub, 0o644)
}

// SignManifest signs the file at manifestPath with the private key at privPath and
// writes the detached signature to manifestPath + ".sig" (the name Stage fetches).
func SignManifest(privPath, manifestPath string) (string, error) {
	key, err := os.ReadFile(privPath)
	if err != nil {
		return "", err
	}
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("signing: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(key), data)
	sigPath := manifestPath + ".sig"
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		return "", err
	}
	return sigPath, nil
}
