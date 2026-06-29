package signing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

// TestSignThenVerify proves the release tool and the device trust check agree: a
// manifest signed here is accepted by otad.VerifyManifestSig, and a tampered one
// is rejected.
func TestSignThenVerify(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "root.key")
	pub := filepath.Join(dir, "root.pub")
	if err := GenerateKeyFiles(priv, pub); err != nil {
		t.Fatal(err)
	}
	man := filepath.Join(dir, "manifest.json")
	body := []byte(`{"version":"v2","rootfs_hash":"abc"}`)
	if err := os.WriteFile(man, body, 0o644); err != nil {
		t.Fatal(err)
	}

	sigPath, err := SignManifest(priv, man)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(sigPath)
	pubKey, _ := os.ReadFile(pub)

	if !otad.VerifyManifestSig(body, sig, pubKey) {
		t.Fatal("daemon rejected a signature the tool produced")
	}
	tampered := append([]byte(nil), body...)
	tampered[1] ^= 0xFF
	if otad.VerifyManifestSig(tampered, sig, pubKey) {
		t.Error("tampered manifest accepted")
	}
}

func TestSignRejectsBadKey(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.key")
	os.WriteFile(bad, []byte("too short"), 0o600)
	man := filepath.Join(dir, "m.json")
	os.WriteFile(man, []byte("{}"), 0o644)
	if _, err := SignManifest(bad, man); err == nil {
		t.Error("expected error on malformed private key")
	}
}
