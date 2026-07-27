package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/signing"
)

func TestVersionNum(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		ok   bool
	}{
		{"v1", 1, true}, {"v2", 2, true}, {"v10", 10, true},
		{"2026.07", 7, true}, {"stable-3", 3, true},
		{"latest", 0, false}, {"", 0, false}, {"v", 0, false},
	}
	for _, c := range cases {
		n, ok := versionNum(c.in)
		if n != c.n || ok != c.ok {
			t.Errorf("versionNum(%q) = (%d,%v), want (%d,%v)", c.in, n, ok, c.n, c.ok)
		}
	}
}

func TestNewer(t *testing.T) {
	// numeric tail wins, and v10 must beat v9 (not string-compare)
	if !newer("v2", "v1") {
		t.Error("v2 should be newer than v1")
	}
	if !newer("v10", "v9") {
		t.Error("v10 should be newer than v9 (numeric, not lexical)")
	}
	if newer("v1", "v2") {
		t.Error("v1 must not be newer than v2")
	}
	if newer("v2", "v2") {
		t.Error("equal versions are not newer")
	}
	// non-numeric falls back to string inequality, never a false 'newer' on equal
	if newer("stable", "stable") {
		t.Error("equal non-numeric must not be newer")
	}
}

func TestWriteReadStateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "status.json")
	want := Status{State: "ready", Current: "v1", Latest: "v2", Percent: 100}
	if err := writeState(p, want); err != nil {
		t.Fatal(err)
	}
	got, ok := readState(p)
	if !ok || got != want {
		t.Fatalf("round-trip: got %+v ok=%v want %+v", got, ok, want)
	}
	if _, ok := readState(filepath.Join(t.TempDir(), "absent.json")); ok {
		t.Error("absent file should return ok=false")
	}
}

// setupFeed serves a signed feed (root -> signing-cert -> manifest) advertising v2 and
// returns the feed URL plus the root public key bytes the caller installs over rootPub.
func setupFeed(t *testing.T) (feed string, rootPubBytes []byte) {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rootfs, kc := write("rootfs.bin", 4096), write("kc.bin", 2048)
	rootPriv, rootPubPath := filepath.Join(dir, "root.key"), filepath.Join(dir, "root.pub")
	if err := signing.GenerateKeyFiles(rootPriv, rootPubPath); err != nil {
		t.Fatal(err)
	}
	cert, signingKey := filepath.Join(dir, "signing-cert.json"), filepath.Join(dir, "signing.key")
	if err := signing.IssueCert(rootPriv, cert, signingKey, 1, 365*24*time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	t.Cleanup(srv.Close)
	manifest := filepath.Join(dir, "manifest.json")
	if _, err := signing.BuildManifest(manifest, "v2", "v1", rootfs, srv.URL+"/rootfs.bin", kc, srv.URL+"/kc.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := signing.SignManifest(signingKey, manifest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(rootPubPath)
	if err != nil {
		t.Fatal(err)
	}
	return srv.URL, b
}

func TestPollOnceFetchStages(t *testing.T) {
	feed, rp := setupFeed(t)
	old := rootPub
	rootPub = rp
	t.Cleanup(func() { rootPub = old })

	work := t.TempDir()
	wal := filepath.Join(work, "deployment.json")
	if err := deployment.New("dev", "v1").Save(wal); err != nil {
		t.Fatal(err)
	}
	c := cfg{
		feed: feed, current: "v1", state: filepath.Join(work, "status.json"), wal: wal,
		rootfsDir: filepath.Join(work, "rootfs"), espDir: filepath.Join(work, "esp"),
		firmwareDir: filepath.Join(work, "firmware"),
	}

	if st := pollOnce(c, false); st.State != "available" {
		t.Fatalf("no-fetch state = %q, want available", st.State)
	}
	if _, err := os.Stat(filepath.Join(c.rootfsDir, "rootfs-next.erofs")); err == nil {
		t.Fatal("no-fetch must not stage the rootfs")
	}

	st := pollOnce(c, true)
	if st.State != "ready" || st.Percent != 100 {
		t.Fatalf("fetch state = %q pct=%d, want ready/100 (err=%q)", st.State, st.Percent, st.Error)
	}
	if err := writeState(c.state, st); err != nil {
		t.Fatal(err)
	}
	if got, ok := readState(c.state); !ok || got.State != "ready" || got.Latest != "v2" {
		t.Fatalf("state file = %+v ok=%v", got, ok)
	}
	if _, err := os.Stat(filepath.Join(c.rootfsDir, "rootfs-next.erofs")); err != nil {
		t.Errorf("rootfs not staged: %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.espDir, "kernelcache-next.efi")); err != nil {
		t.Errorf("kernelcache not staged: %v", err)
	}
}
