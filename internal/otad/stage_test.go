package otad

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// stageServer serves a signed manifest + the two artifacts. Returns the base URL,
// the manifest signing pubkey, and a handle to break the signature.
func stageServer(t *testing.T, tamperSig bool) (string, []byte) {
	t.Helper()
	rootfs := []byte("EROFS rootfs image v2 contents")
	kernel := []byte("UKI kernelcache v2 contents")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	mux := http.NewServeMux()
	mux.HandleFunc("/rootfs", func(w http.ResponseWriter, r *http.Request) { w.Write(rootfs) })
	mux.HandleFunc("/kernelcache", func(w http.ResponseWriter, r *http.Request) { w.Write(kernel) })

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	m := Manifest{
		Version:         "v2",
		MinVersion:      "v1",
		RootFSURL:       srv.URL + "/rootfs",
		RootFSHash:      sha256hex(rootfs),
		KernelcacheURL:  srv.URL + "/kernelcache",
		KernelcacheHash: sha256hex(kernel),
	}
	mData, _ := json.Marshal(m)
	sig := ed25519.Sign(priv, mData)
	if tamperSig {
		sig[0] ^= 0xFF
	}
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mData) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(sig) })
	return srv.URL, pub
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
	base, pub := stageServer(t, false)
	wal := newWALFile(t)
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}

	msg, err := Stage(context.Background(), wal, base+"/manifest.json", pub, dirs)
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
}

func TestStageRejectsBadSignature(t *testing.T) {
	base, pub := stageServer(t, true) // tampered signature
	wal := newWALFile(t)
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}

	if _, err := Stage(context.Background(), wal, base+"/manifest.json", pub, dirs); err == nil {
		t.Fatal("Stage must reject a bad manifest signature")
	}
	// WAL untouched: no pending candidate from a rejected update.
	d, _ := deployment.Load(wal)
	if d.HasPending() {
		t.Errorf("rejected update still marked the WAL pending: %+v", d.RootFS)
	}
}
