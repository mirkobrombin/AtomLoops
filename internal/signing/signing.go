// Package signing is the release-side counterpart to the daemon's trust checks:
// it produces the Ed25519 keypair and the detached manifest signatures that
// otad.Stage (and the loader) verify. Kept separate from the device code because
// this runs where updates are built, not on the device.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
)

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
