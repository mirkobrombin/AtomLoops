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
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

// signedFeedV2 serves a full two-tier release (root-signed signing cert + signing-key-
// signed manifest + artifacts) for version v2 with the given dm-verity root hash. Returns
// the base URL and the ROOT public key. Same shape the daemon fetches in production.
func signedFeedV2(t *testing.T, verityHash string) (string, []byte) {
	t.Helper()
	rootfs := []byte("EROFS rootfs image v2")
	kernel := []byte("UKI kernelcache v2")
	h := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	cert := trust.SigningCert{
		Version:       1,
		SigningPubkey: base64.StdEncoding.EncodeToString(signPub),
		IssuedAt:      "2026-01-01T00:00:00Z",
		NotAfter:      "2099-01-01T00:00:00Z",
	}
	certBytes, _ := json.Marshal(cert)
	certSig := ed25519.Sign(rootPriv, certBytes)

	mux := http.NewServeMux()
	mux.HandleFunc("/rootfs", func(w http.ResponseWriter, r *http.Request) { w.Write(rootfs) })
	mux.HandleFunc("/kernelcache", func(w http.ResponseWriter, r *http.Request) { w.Write(kernel) })
	rootfsHashTree := []byte("dm-verity hash tree for rootfs v2")
	kernelSig := []byte("ed25519 signature over kernelcache v2")
	mux.HandleFunc("/rootfs-hashtree", func(w http.ResponseWriter, r *http.Request) { w.Write(rootfsHashTree) })
	mux.HandleFunc("/kernelcache-sig", func(w http.ResponseWriter, r *http.Request) { w.Write(kernelSig) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	m := Manifest{
		Version:            "v2",
		MinVersion:         "v1",
		RootFSURL:          srv.URL + "/rootfs",
		RootFSHash:         h(rootfs),
		RootFSVerityHash:   verityHash,
		KernelcacheURL:     srv.URL + "/kernelcache",
		KernelcacheHash:    h(kernel),
		RootFSHashTreeURL:  srv.URL + "/rootfs-hashtree",
		RootFSHashTreeHash: h(rootfsHashTree),
		KernelcacheSigURL:  srv.URL + "/kernelcache-sig",
		KernelcacheSigHash: h(kernelSig),
	}
	mData, _ := json.Marshal(m)
	mSig := ed25519.Sign(signPriv, mData)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mData) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(mSig) })
	mux.HandleFunc("/signing-cert.json", func(w http.ResponseWriter, r *http.Request) { w.Write(certBytes) })
	mux.HandleFunc("/signing-cert.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(certSig) })
	return srv.URL, rootPub
}

func e2eWAL(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "deployment.json")
	if err := deployment.New("dev-1", "v1").Save(p); err != nil {
		t.Fatal(err)
	}
	return p
}

// bootedAs points the daemon's /proc/cmdline reader at a synthetic cmdline that carries
// the given verity hash, simulating the slot the loader actually booted.
func bootedAs(t *testing.T, version, verityHash string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(p, []byte("console=ttyS0 ATOM_ROOT_HASH="+verityHash+" ATOM_VERSION="+version+" ro\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := bootedVersionPath
	bootedVersionPath = p
	t.Cleanup(func() { bootedVersionPath = old })
}

// TestOTACycleEndToEnd exercises the whole update: fetch+verify+stage a signed v2, then
// three good boots OF THE CANDIDATE confirm and promote it to last_known_good.
func TestOTACycleEndToEnd(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	base, rootPub := signedFeedV2(t, "verity-v2")
	wal := e2eWAL(t)
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}
	health := t.TempDir() // empty => healthy

	// 1. stage the candidate
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	d, _ := deployment.Load(wal)
	if d.RootFS.Pending != "v2" || d.RootFS.PendingHash != "verity-v2" {
		t.Fatalf("candidate not staged: %+v", d.RootFS)
	}

	// 2. the loader booted the candidate (cmdline carries verity-v2)
	bootedAs(t, "v2", "verity-v2")

	// 3. three good boots -> promotion
	var last string
	for i := 0; i < 3; i++ {
		msg, err := BootSuccess(wal, health, nil, StageDirs{})
		if err != nil {
			t.Fatalf("BootSuccess %d: %v", i, err)
		}
		last = msg
	}
	d, _ = deployment.Load(wal)
	if d.HasPending() || d.RootFS.Current != "v2" || d.RootFS.LastKnownGood != "v2" {
		t.Fatalf("candidate not promoted after 3 good boots (%q): %+v", last, d.RootFS)
	}
}

// TestOTACycleRollback exercises the safety net: a staged candidate the loader FELL BACK
// away from (cmdline carries the old hash) is never confirmed, and the spent trial budget
// rolls the WAL back to last_known_good.
func TestOTACycleRollback(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	base, rootPub := signedFeedV2(t, "verity-v2")
	wal := e2eWAL(t)
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}
	health := t.TempDir()

	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	// the loader fell back to the OLD slot: cmdline carries verity-v1, not the candidate's.
	bootedAs(t, "v1", "verity-v1")

	d0, _ := deployment.Load(wal)
	for i := 0; i < d0.RootFS.MaxAttempts+1; i++ {
		if _, err := BootSuccess(wal, health, nil, StageDirs{}); err != nil {
			t.Fatalf("BootSuccess %d: %v", i, err)
		}
	}
	d, _ := deployment.Load(wal)
	if d.RootFS.Current != "v1" || d.RootFS.Current == "v2" {
		t.Fatalf("dead candidate not rolled back: %+v", d.RootFS)
	}
}
