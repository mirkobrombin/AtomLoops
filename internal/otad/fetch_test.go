package otad

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func fastRetries(t *testing.T) {
	oldDelay, oldStall := retryDelay, stallTimeout
	retryDelay, stallTimeout = time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { retryDelay, stallTimeout = oldDelay, oldStall })
}

func TestFetchToRetriesServerErrors(t *testing.T) {
	fastRetries(t)
	var attempts int32
	body := []byte("rootfs after a bad gateway")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "rootfs.erofs")
	if _, err := FetchTo(context.Background(), srv.URL, dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); string(got) != string(body) {
		t.Fatalf("fetched %q", got)
	}
}

func TestFetchToGivesUpOnNotFound(t *testing.T) {
	fastRetries(t)
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if _, err := FetchTo(context.Background(), srv.URL, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("404 accepted")
	}
	if attempts != 1 {
		t.Fatalf("404 retried %d times", attempts)
	}
}

func TestFetchToResumesCutDownload(t *testing.T) {
	fastRetries(t)
	body := make([]byte, 256*1024)
	rand.Read(body)
	var ranges []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ranges = append(ranges, r.Header.Get("Range"))
		first := len(ranges) == 1
		mu.Unlock()
		if first {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Write(body[:100000])
			w.(http.Flusher).Flush()
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		http.ServeContent(w, r, "rootfs.erofs", time.Time{}, bytes.NewReader(body))
	}))
	defer srv.Close()
	var last int64
	ctx := WithProgress(context.Background(), func(done, total int64) { last = done })
	dest := filepath.Join(t.TempDir(), "rootfs.erofs")
	n, err := FetchTo(ctx, srv.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if n != int64(len(body)) || !bytes.Equal(got, body) || last != int64(len(body)) {
		t.Fatalf("n=%d progress=%d equal=%v", n, last, bytes.Equal(got, body))
	}
	if len(ranges) != 2 || ranges[1] != "bytes=100000-" {
		t.Fatalf("ranges %q", ranges)
	}
}

func TestFetchToAbandonsStalledDownload(t *testing.T) {
	fastRetries(t)
	fetchAttemptsOld := fetchAttempts
	fetchAttempts = 2
	defer func() { fetchAttempts = fetchAttemptsOld }()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.Write([]byte("abc"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	start := time.Now()
	_, err := FetchTo(context.Background(), srv.URL, filepath.Join(t.TempDir(), "x"))
	if err == nil {
		t.Fatal("stalled download accepted")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("stall detected after %v", time.Since(start))
	}
}
