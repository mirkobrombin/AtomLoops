package otad

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/internal/trust"
)

// signedAnchor builds a root-signed cert + a manifest signed by that cert's signing
// key, returning the four anchor byte blobs and the ROOT public key a device bakes in.
func signedAnchor(t *testing.T, withFirmware bool) (manifest, manifestSig, cert, certSig, rootPub []byte) {
	t.Helper()
	rPub, rPriv, _ := ed25519.GenerateKey(rand.Reader)
	sPub, sPriv, _ := ed25519.GenerateKey(rand.Reader)
	c := trust.SigningCert{
		Version:       1,
		SigningPubkey: base64.StdEncoding.EncodeToString(sPub),
		IssuedAt:      "2026-01-01T00:00:00Z",
		NotAfter:      "2099-01-01T00:00:00Z",
	}
	cert, _ = json.Marshal(c)
	certSig = ed25519.Sign(rPriv, cert)
	m := Manifest{Version: "v2", MinVersion: "v1", RootFSURL: "http://x/r", RootFSHash: "aa", KernelcacheURL: "http://x/k", KernelcacheHash: "bb"}
	if withFirmware {
		m.FirmwareURL = "http://x/fw"
		m.FirmwareHash = "cc"
		m.FirmwareVerityHash = "feedface00112233"
		m.FirmwareHashTreeURL = "http://x/fw.hash"
		m.FirmwareHashTreeHash = "dd"
		m.FirmwareVersion = 5
	}
	manifest, _ = json.Marshal(m)
	manifestSig = ed25519.Sign(sPriv, manifest)
	return manifest, manifestSig, cert, certSig, rPub
}

func TestFirmwareAnchorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	manifest, manifestSig, cert, certSig, rootPub := signedAnchor(t, true)
	if err := WriteFirmwareAnchor(dir, "active", manifest, manifestSig, cert, certSig); err != nil {
		t.Fatalf("write: %v", err)
	}
	hash, ver, err := VerifyFirmwareAnchor(dir, "active", rootPub, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), "default")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if hash != "feedface00112233" || ver != 5 {
		t.Fatalf("got hash=%q ver=%d, want feedface00112233/5", hash, ver)
	}
}

func TestFirmwareAnchorRejectsTamperedManifest(t *testing.T) {
	dir := t.TempDir()
	manifest, manifestSig, cert, certSig, rootPub := signedAnchor(t, true)
	manifest = append(manifest, ' ') // any byte change breaks the signature
	if err := WriteFirmwareAnchor(dir, "active", manifest, manifestSig, cert, certSig); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyFirmwareAnchor(dir, "active", rootPub, time.Now(), "default"); err == nil {
		t.Fatal("tampered manifest must be refused")
	}
}

func TestFirmwareAnchorRejectsWrongRoot(t *testing.T) {
	dir := t.TempDir()
	manifest, manifestSig, cert, certSig, _ := signedAnchor(t, true)
	if err := WriteFirmwareAnchor(dir, "active", manifest, manifestSig, cert, certSig); err != nil {
		t.Fatal(err)
	}
	otherRoot, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := VerifyFirmwareAnchor(dir, "active", otherRoot, time.Now(), "default"); err == nil {
		t.Fatal("cert not signed by the baked root must be refused")
	}
}

func TestFirmwareAnchorRejectsNoFirmware(t *testing.T) {
	dir := t.TempDir()
	manifest, manifestSig, cert, certSig, rootPub := signedAnchor(t, false) // manifest without a firmware track
	if err := WriteFirmwareAnchor(dir, "active", manifest, manifestSig, cert, certSig); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyFirmwareAnchor(dir, "active", rootPub, time.Now(), "default"); err == nil {
		t.Fatal("a manifest with no firmware verity hash must not yield a boot anchor")
	}
}

func TestFirmwareAnchorMissingIsError(t *testing.T) {
	if _, _, err := VerifyFirmwareAnchor(t.TempDir(), "active", nil, time.Now(), "default"); err == nil {
		t.Fatal("absent anchor must be an error so the caller falls open to base firmware")
	}
}

func TestFirmwareAnchorActivateAndRollback(t *testing.T) {
	dir := t.TempDir()
	// An existing active anchor (old firmware).
	oldM, oldMS, oldC, oldCS, oldRoot := signedAnchor(t, true)
	if err := WriteFirmwareAnchor(dir, "active", oldM, oldMS, oldC, oldCS); err != nil {
		t.Fatal(err)
	}
	// Stage a new candidate as -next.
	newM, newMS, newC, newCS, newRoot := signedAnchor(t, true)
	if err := WriteFirmwareAnchor(dir, "next", newM, newMS, newC, newCS); err != nil {
		t.Fatal(err)
	}
	if err := ActivateFirmwareAnchor(dir); err != nil {
		t.Fatalf("activate: %v", err)
	}
	// After activation the active anchor verifies against the NEW root, not the old.
	if _, _, err := VerifyFirmwareAnchor(dir, "active", newRoot, time.Now(), "default"); err != nil {
		t.Fatalf("activated anchor should verify with new root: %v", err)
	}
	if _, _, err := VerifyFirmwareAnchor(dir, "active", oldRoot, time.Now(), "default"); err == nil {
		t.Fatal("activated anchor must no longer verify with the old root")
	}
	// Rollback restores the previous active anchor.
	if err := RollbackFirmwareAnchor(dir); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, _, err := VerifyFirmwareAnchor(dir, "active", oldRoot, time.Now(), "default"); err != nil {
		t.Fatalf("rollback should restore the old anchor: %v", err)
	}
}
