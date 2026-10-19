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
	"strings"
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

func TestFetchToFollowsRedirects(t *testing.T) {
	body := []byte("release asset")
	mux := http.NewServeMux()
	mux.HandleFunc("/asset", func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	mux.HandleFunc("/hop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/asset", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/hop", http.StatusFound) })
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", http.StatusFound) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "asset")
	if _, err := FetchTo(context.Background(), srv.URL+"/start", dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); string(got) != string(body) {
		t.Fatalf("fetched %q, want %q", got, body)
	}
	if _, err := FetchTo(context.Background(), srv.URL+"/loop", filepath.Join(t.TempDir(), "loop")); err == nil {
		t.Fatal("a redirect loop was followed forever")
	}
}

func TestFetchToRefusesHTTPSDowngrade(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer secure.Close()
	old := http.DefaultTransport
	http.DefaultTransport = secure.Client().Transport
	defer func() { http.DefaultTransport = old }()
	_, err := FetchTo(context.Background(), secure.URL, filepath.Join(t.TempDir(), "x"))
	if err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("https redirect to http: %v", err)
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
