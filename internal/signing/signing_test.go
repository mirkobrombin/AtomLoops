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

func TestBuildManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs.erofs")
	kc := filepath.Join(dir, "kc.efi")
	os.WriteFile(rootfs, []byte("EROFS bytes v2"), 0o644)
	os.WriteFile(kc, []byte("UKI bytes v2"), 0o644)

	out := filepath.Join(dir, "manifest.json")
	if _, err := BuildManifest(out, "v2", "v1", rootfs, "https://x/rootfs", kc, "https://x/kc"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	m, err := otad.ParseManifest(b)
	if err != nil {
		t.Fatalf("generated manifest does not parse: %v", err)
	}
	if m.Version != "v2" || m.MinVersion != "v1" {
		t.Errorf("versions wrong: %+v", m)
	}
	// The recorded hashes must match what the daemon's own verifier computes.
	if err := otad.VerifySHA256(rootfs, m.RootFSHash); err != nil {
		t.Errorf("rootfs hash mismatch: %v", err)
	}
	if err := otad.VerifySHA256(kc, m.KernelcacheHash); err != nil {
		t.Errorf("kernelcache hash mismatch: %v", err)
	}
}
