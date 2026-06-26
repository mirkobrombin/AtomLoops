package otad

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestFetchToHappyPath(t *testing.T) {
	body := []byte("atom loops manifest bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "manifest.json")
	n, err := FetchTo(context.Background(), srv.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if int(n) != len(body) || string(got) != string(body) {
		t.Fatalf("fetched %q (%d), want %q", got, n, body)
	}
	// No leftover temp file.
	if _, err := os.Stat(dest + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind")
	}
}

// TestFetchToRetriesTransport drops the connection on the first attempt (a real
// transport error) and serves on the second, proving go-foundation's httpx retry
// is wired: without it, the fetch would fail.
func TestFetchToRetriesTransport(t *testing.T) {
	var attempts int32
	body := []byte("second-attempt body")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			// Hijack and close without a response -> the client sees a transport
			// error and httpx retries.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("no hijacker")
			}
			conn, _, _ := hj.Hijack()
			conn.(net.Conn).Close()
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "artifact")
	if _, err := FetchTo(context.Background(), srv.URL, dest); err != nil {
		t.Fatalf("fetch should have recovered via retry: %v", err)
	}
	if atomic.LoadInt32(&attempts) < 2 {
		t.Errorf("expected a retry (>=2 attempts), got %d", attempts)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(body) {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestVerifyManifestSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte(`{"version":"v2","rootfs_hash":"..."}`)
	sig := ed25519.Sign(priv, data)

	if !VerifyManifestSig(data, sig, pub) {
		t.Error("valid signature rejected")
	}
	bad := append([]byte(nil), data...)
	bad[0] ^= 0xFF
	if VerifyManifestSig(bad, sig, pub) {
		t.Error("tampered data accepted")
	}
	if VerifyManifestSig(data, sig, pub[:16]) {
		t.Error("short pubkey accepted")
	}
}
