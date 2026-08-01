package otad

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// stageServer builds the full two-tier release: a root-signed signing cert, a
// manifest signed by that signing key, and the two artifacts. Returns the base URL
// and the ROOT public key the daemon embeds. tamperManifestSig breaks the manifest
// signature to exercise rejection.
func stageServer(t *testing.T, tamperManifestSig bool) (string, []byte) {
	t.Helper()
	rootfs := []byte("EROFS rootfs image v2 contents")
	kernel := []byte("UKI kernelcache v2 contents")

	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Root-signed signing cert (v1), valid for a year.
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
		RootFSHash:         sha256hex(rootfs),
		KernelcacheURL:     srv.URL + "/kernelcache",
		KernelcacheHash:    sha256hex(kernel),
		RootFSHashTreeURL:  srv.URL + "/rootfs-hashtree",
		RootFSHashTreeHash: sha256hex(rootfsHashTree),
		KernelcacheSigURL:  srv.URL + "/kernelcache-sig",
		KernelcacheSigHash: sha256hex(kernelSig),
	}
	mData, _ := json.Marshal(m)
	mSig := ed25519.Sign(signPriv, mData) // signed by the SIGNING key
	if tamperManifestSig {
		mSig[0] ^= 0xFF
	}

	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mData) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(mSig) })
	mux.HandleFunc("/signing-cert.json", func(w http.ResponseWriter, r *http.Request) { w.Write(certBytes) })
	mux.HandleFunc("/signing-cert.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(certSig) })
	return srv.URL, rootPub
}

func newWALFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "deployment.json")
	if err := deployment.New("dev-1", "v1").Save(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStageEndToEnd(t *testing.T) {
	base, rootPub := stageServer(t, false)
	wal := newWALFile(t)
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}

	msg, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dirs.Rootfs, "rootfs-next.erofs")); err != nil {
		t.Errorf("rootfs not staged: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dirs.ESP, "kernelcache-next.efi")); err != nil {
		t.Errorf("kernelcache not staged: %v", err)
	}
	d, _ := deployment.Load(wal)
	if d.RootFS.Pending != "v2" || d.RootFS.BootAttempts != 3 {
		t.Fatalf("WAL not marked pending: %+v (%s)", d.RootFS, msg)
	}
	// The ESP boot-state was armed to boot -next.
	bs, _ := ReadBootState(filepath.Join(dirs.ESP, "boot-state"))
	if bs.Target != "next" || !bs.Trial {
		t.Errorf("boot-state not armed: %+v", bs)
	}
}

func TestStageExpectedManifest(t *testing.T) {
	base, rootPub := stageServer(t, false)
	resp, err := http.Get(base + "/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	wal := newWALFile(t)
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}
	if _, err := StageExpectedManifest(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs, sha256hex(manifest)); err != nil {
		t.Fatalf("StageExpectedManifest matching digest: %v", err)
	}

	wal = newWALFile(t)
	dirs = StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}
	if _, err := StageExpectedManifest(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "manifest changed since update check") {
		t.Fatalf("StageExpectedManifest wrong digest = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dirs.Rootfs, "rootfs-next.erofs")); !os.IsNotExist(err) {
		t.Fatalf("wrong manifest digest staged rootfs: %v", err)
	}
}

func TestStageRejectsBadSignature(t *testing.T) {
	base, rootPub := stageServer(t, true) // tampered manifest signature
	wal := newWALFile(t)
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}

	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err == nil {
		t.Fatal("Stage must reject a bad manifest signature")
	}
	d, _ := deployment.Load(wal)
	if d.HasPending() {
		t.Errorf("rejected update still marked the WAL pending: %+v", d.RootFS)
	}
}

func TestStageRejectsWrongRoot(t *testing.T) {
	base, _ := stageServer(t, false)
	wal := newWALFile(t)
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "r"), ESP: filepath.Join(t.TempDir(), "e")}
	// A different root key than the one that signed the cert: cert verify must fail.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", otherPub, dirs); err == nil {
		t.Fatal("Stage must reject a cert not signed by the trusted root")
	}
}

func TestStageRefusesDowngrade(t *testing.T) {
	base, rootPub := stageServer(t, false)
	wal := filepath.Join(t.TempDir(), "deployment.json")
	if err := deployment.New("dev-1", "v5").Save(wal); err != nil {
		t.Fatal(err)
	}
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "r"), ESP: filepath.Join(t.TempDir(), "e")}
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err == nil {
		t.Fatal("Stage must refuse a downgrade (v2 < installed v5)")
	}
	d, _ := deployment.Load(wal)
	if d.HasPending() {
		t.Errorf("refused downgrade still marked pending: %+v", d.RootFS)
	}
}

func TestVersionNum(t *testing.T) {
	if n, ok := versionNum("v43"); !ok || n != 43 {
		t.Errorf("versionNum(v43) = %d,%v", n, ok)
	}
	if !isDowngrade("v2", "v5") || isDowngrade("v6", "v5") || isDowngrade("x", "y") {
		t.Error("isDowngrade wrong")
	}
}
