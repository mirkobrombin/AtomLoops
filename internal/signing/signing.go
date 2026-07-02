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
func BuildManifest(outPath, version, minVersion, rootfsFile, rootfsURL, kcFile, kcURL string) (string, error) {
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
