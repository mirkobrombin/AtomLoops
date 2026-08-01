package signing

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/trust"
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
	spec := ReleaseSpec{
		Version: "v2", MinVersion: "v1",
		ProductName: "Sinty OS Event Horizon", ProductVersion: "26", ProductBuild: "26A010",
		RootFSFile: rootfs, RootFSURL: "https://x/rootfs",
		RootFSVerityHash:   "deadbeefcafe",
		RootFSHashTreeFile: rootfs, RootFSHashTreeURL: "https://x/rootfs.hash",
		KernelcacheFile: kc, KernelcacheURL: "https://x/kc",
		KernelcacheSigFile: kc, KernelcacheSigURL: "https://x/kc.sig",
	}
	if _, err := BuildManifest(out, spec); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	m, err := otad.ParseManifest(b)
	if err != nil {
		t.Fatalf("generated manifest does not parse: %v", err)
	}
	if m.Version != "v2" || m.MinVersion != "v1" || m.ProductName != "Sinty OS Event Horizon" || m.ProductVersion != "26" || m.ProductBuild != "26A010" {
		t.Errorf("versions wrong: %+v", m)
	}
	// The recorded hashes must match what the daemon's own verifier computes.
	if err := otad.VerifySHA256(rootfs, m.RootFSHash); err != nil {
		t.Errorf("rootfs hash mismatch: %v", err)
	}
	if err := otad.VerifySHA256(kc, m.KernelcacheHash); err != nil {
		t.Errorf("kernelcache hash mismatch: %v", err)
	}
	spec.ProductVersion = " 26"
	if _, err := BuildManifest(out, spec); err == nil {
		t.Error("invalid product metadata accepted")
	}
}

func TestTwoTierTrustChain(t *testing.T) {
	dir := t.TempDir()
	rootPriv := filepath.Join(dir, "root.key")
	rootPub := filepath.Join(dir, "root.pub")
	if err := GenerateKeyFiles(rootPriv, rootPub); err != nil {
		t.Fatal(err)
	}
	rootPubB, _ := os.ReadFile(rootPub)

	// Root issues a signing cert (v3) + the operational signing key.
	cert := filepath.Join(dir, "signing-cert-v3.json")
	signKey := filepath.Join(dir, "signing-v3.key")
	issued := time.Unix(1_000_000, 0)
	if err := IssueCert(rootPriv, cert, signKey, 3, 365*24*time.Hour, issued); err != nil {
		t.Fatal(err)
	}

	// A manifest signed by the SIGNING key (not root).
	man := filepath.Join(dir, "manifest.json")
	os.WriteFile(man, []byte(`{"version":"v2"}`), 0o644)
	if _, err := SignManifest(signKey, man); err != nil {
		t.Fatal(err)
	}

	// Chain: cert verifies vs root -> signing pubkey; manifest verifies vs it.
	certB, _ := os.ReadFile(cert)
	certSig, _ := os.ReadFile(cert + ".sig")
	signingPub, ver, err := trust.VerifyCert(certB, certSig, rootPubB, issued.Add(24*time.Hour))
	if err != nil || ver != 3 {
		t.Fatalf("VerifyCert: ver=%d err=%v", ver, err)
	}
	manB, _ := os.ReadFile(man)
	manSig, _ := os.ReadFile(man + ".sig")
	if !trust.Verify(manB, manSig, signingPub) {
		t.Fatal("manifest not verified by the signing key from the cert")
	}

	// Expired cert is refused.
	if _, _, err := trust.VerifyCert(certB, certSig, rootPubB, issued.Add(400*24*time.Hour)); err == nil {
		t.Error("expired cert accepted")
	}
	// Tampered cert fails the root check.
	bad := append([]byte(nil), certB...)
	bad[10] ^= 0xFF
	if _, _, err := trust.VerifyCert(bad, certSig, rootPubB, issued.Add(24*time.Hour)); err == nil {
		t.Error("tampered cert accepted")
	}

	// Revocation: min v4 shuts out v3, passes v4.
	rev := filepath.Join(dir, "revocation.json")
	if err := Revoke(rootPriv, rev, 4, nil, issued); err != nil {
		t.Fatal(err)
	}
	revB, _ := os.ReadFile(rev)
	revSig, _ := os.ReadFile(rev + ".sig")
	if err := trust.CheckRevocation(revB, revSig, rootPubB, 3); err == nil {
		t.Error("v3 should be revoked (below min v4)")
	}
	if err := trust.CheckRevocation(revB, revSig, rootPubB, 4); err != nil {
		t.Errorf("v4 should pass: %v", err)
	}
	// Explicit revoke of v5.
	Revoke(rootPriv, rev, 1, []int{5}, issued)
	revB, _ = os.ReadFile(rev)
	revSig, _ = os.ReadFile(rev + ".sig")
	if err := trust.CheckRevocation(revB, revSig, rootPubB, 5); err == nil {
		t.Error("v5 explicitly revoked should fail")
	}
}
