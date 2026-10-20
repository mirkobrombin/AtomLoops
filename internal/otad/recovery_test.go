package otad

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

func newRecoveryFeed(t *testing.T, image, imageSig []byte) (string, []byte) {
	t.Helper()
	h := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	cert := trust.SigningCert{Version: 1, SigningPubkey: base64.StdEncoding.EncodeToString(signPub),
		IssuedAt: "2026-01-01T00:00:00Z", NotAfter: "2099-01-01T00:00:00Z"}
	certBytes, _ := json.Marshal(cert)
	certSig := ed25519.Sign(rootPriv, certBytes)
	if imageSig == nil {
		imageSig = ed25519.Sign(signPriv, image)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	m := Manifest{
		Version: "v2", MinVersion: "v1",
		RootFSURL: srv.URL + "/rootfs", RootFSHash: h([]byte("rootfs")),
		KernelcacheURL: srv.URL + "/kernelcache", KernelcacheHash: h([]byte("kernelcache")),
		RecoveryVersion: 3,
		RecoveryURL:     srv.URL + "/recovery", RecoveryHash: h(image),
		RecoverySigURL: srv.URL + "/recovery-sig", RecoverySigHash: h(imageSig),
	}
	mData, _ := json.Marshal(m)
	mSig := ed25519.Sign(signPriv, mData)
	serve := func(b []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { w.Write(b) }
	}
	mux.HandleFunc("/recovery", serve(image))
	mux.HandleFunc("/recovery-sig", serve(imageSig))
	mux.HandleFunc("/manifest.json", serve(mData))
	mux.HandleFunc("/manifest.json.sig", serve(mSig))
	mux.HandleFunc("/signing-cert.json", serve(certBytes))
	mux.HandleFunc("/signing-cert.json.sig", serve(certSig))
	return srv.URL + "/manifest.json", rootPub
}

func recoveryDirs(t *testing.T) StageDirs {
	t.Helper()
	dirs := loaderDirs(t, []byte("MZ loader"))
	os.WriteFile(filepath.Join(dirs.ESP, recoveryFile), []byte("MZ old recovery"), 0o644)
	os.WriteFile(filepath.Join(dirs.ESP, recoveryFile+".sig"), []byte("old sig"), 0o644)
	return dirs
}

func TestStageRecoveryInstallsVerifiedImage(t *testing.T) {
	img := []byte("MZ new recovery image")
	manifest, rootPub := newRecoveryFeed(t, img, nil)
	dirs := recoveryDirs(t)
	wal := e2eWAL(t)

	msg, err := StageRecovery(context.Background(), wal, manifest, "", rootPub, dirs)
	if err != nil || !strings.Contains(msg, "version 3 installed") {
		t.Fatalf("StageRecovery = %q, %v", msg, err)
	}
	if got := readFileT(t, filepath.Join(dirs.ESP, recoveryFile)); got != string(img) {
		t.Fatal("recovery image not installed")
	}
	for _, f := range []string{recoveryNextFile, recoveryPrevFile, recoveryPrevFile + ".sig"} {
		if _, err := os.Stat(filepath.Join(dirs.ESP, f)); err == nil {
			t.Fatalf("%s left behind", f)
		}
	}
	d, _ := deployment.Load(wal)
	if d.Recovery.Version != "3" {
		t.Fatalf("WAL recovery version = %q", d.Recovery.Version)
	}
	msg, err = StageRecovery(context.Background(), wal, manifest, "", rootPub, dirs)
	if err != nil || msg != "recovery: already current" {
		t.Fatalf("second StageRecovery = %q, %v", msg, err)
	}
}

func TestStageRecoveryRefusesBadSignature(t *testing.T) {
	img := []byte("MZ tampered recovery")
	manifest, rootPub := newRecoveryFeed(t, img, make([]byte, ed25519.SignatureSize))
	dirs := recoveryDirs(t)
	if _, err := StageRecovery(context.Background(), e2eWAL(t), manifest, "", rootPub, dirs); err == nil {
		t.Fatal("bad signature accepted")
	}
	if got := readFileT(t, filepath.Join(dirs.ESP, recoveryFile)); got != "MZ old recovery" {
		t.Fatal("installed recovery touched by a refused update")
	}
	if _, err := os.Stat(filepath.Join(dirs.ESP, recoveryNextFile)); err == nil {
		t.Fatal("refused download left on the ESP")
	}
}

func TestRepairRecoverySlotRestoresInterruptedSwap(t *testing.T) {
	dirs := recoveryDirs(t)
	cur := filepath.Join(dirs.ESP, recoveryFile)
	prev := filepath.Join(dirs.ESP, recoveryPrevFile)
	os.Rename(cur, prev)
	os.Rename(cur+".sig", prev+".sig")
	msg, err := RepairRecoverySlot(dirs)
	if err != nil || msg == "" {
		t.Fatalf("RepairRecoverySlot = %q, %v", msg, err)
	}
	if got := readFileT(t, cur); got != "MZ old recovery" {
		t.Fatal("previous recovery not restored")
	}
}
