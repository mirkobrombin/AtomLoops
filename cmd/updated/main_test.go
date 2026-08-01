package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/signing"
)

func TestVersionNum(t *testing.T) {
	cases := []struct {
		in string
		n  int
		ok bool
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
	want := Status{
		State: "ready", Current: "v1", Latest: "v2", Percent: 100,
		ProductName: "Sinty OS Event Horizon", ProductVersion: "26", ProductBuild: "26A010",
		manifestSHA256: strings.Repeat("a", 64),
	}
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

func TestStatusJSONOmitsAbsentProductMetadata(t *testing.T) {
	b, err := json.Marshal(Status{
		State: "available", Current: "v1", Latest: "v2",
		manifestSHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "product_") {
		t.Fatalf("legacy status grew product fields: %s", b)
	}
	if strings.Contains(string(b), "manifest") {
		t.Fatalf("public status exposed internal manifest digest: %s", b)
	}
}

func TestStatusStoreClaimsDownloadOnce(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "status.json")
	available := Status{
		State: "available", Current: "v1", Latest: "v2",
		ProductName: "Sinty OS Event Horizon", ProductVersion: "26", ProductBuild: "26A010",
		manifestSHA256: strings.Repeat("a", 64),
	}
	if err := writeState(statePath, available); err != nil {
		t.Fatal(err)
	}
	store := statusStore{statePath: statePath}
	advertised := store.getForClient()
	if advertised.State != "available" {
		t.Fatalf("advertised status = %+v, want available", advertised)
	}
	consentToken := clientStatus(advertised).ConsentToken
	if consentToken == "" {
		t.Fatal("advertised status has no consent token")
	}
	newer := available
	newer.Latest = "v3"
	newer.ProductVersion = "26.1"
	newer.ProductBuild = "26A011"
	newer.manifestSHA256 = strings.Repeat("b", 64)
	if _, err := store.publishPoll(newer); err != nil {
		t.Fatal(err)
	}

	var claims atomic.Int32
	var ready sync.WaitGroup
	start := make(chan struct{})
	for range 16 {
		ready.Add(1)
		go func() {
			defer ready.Done()
			<-start
			if _, ok := store.claimDownload(consentToken); ok {
				claims.Add(1)
			}
		}()
	}
	close(start)
	ready.Wait()

	if got := claims.Load(); got != 1 {
		t.Fatalf("download claims = %d, want 1", got)
	}
	if got := store.get(); got.State != "downloading" || got.Latest != "v2" {
		t.Fatalf("claimed status = %+v, want downloading v2", got)
	}
	if got, err := store.publishPoll(available); err != nil || got.State != "downloading" {
		t.Fatalf("poll replaced active download: %+v", got)
	}
	if got := store.get(); got.ProductVersion != "26" || got.ProductBuild != "26A010" {
		t.Fatalf("download dropped product metadata: %+v", got)
	}
}

func TestStatusStoreRejectsReplacedConsentToken(t *testing.T) {
	store := statusStore{}
	v2 := Status{State: "available", Latest: "v2", manifestSHA256: strings.Repeat("a", 64)}
	oldToken := clientStatus(store.advertise(v2)).ConsentToken
	v3 := Status{State: "available", Latest: "v3", manifestSHA256: strings.Repeat("b", 64)}
	newToken := clientStatus(store.advertise(v3)).ConsentToken

	if _, ok := store.claimDownload(oldToken); ok {
		t.Fatal("replaced consent token claimed a different manifest")
	}
	claimed, ok := store.claimDownload(newToken)
	if !ok || claimed.Latest != "v3" {
		t.Fatalf("current consent token claim = %+v ok=%v, want v3", claimed, ok)
	}
}

func TestStageLockExcludesOtherProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stage.lock")
	first, err := acquireStageLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = syscall.Flock(int(first.Fd()), syscall.LOCK_UN)
		_ = first.Close()
	}()

	if second, err := acquireStageLock(path); !errors.Is(err, errStageBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second lock = %v, want errStageBusy", err)
	}
}

func TestRebootClaimSharesStageLock(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "status.json")
	lockPath := filepath.Join(dir, "stage.lock")
	if err := writeState(statePath, Status{State: "ready", Current: "v1", Latest: "v2"}); err != nil {
		t.Fatal(err)
	}
	statuses := statusStore{statePath: statePath}
	c := cfg{stageLock: lockPath}

	staging, err := acquireStageLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if reboot, err := claimReboot(c, &statuses); !errors.Is(err, errStageBusy) {
		if reboot != nil {
			releaseStageLock(reboot)
		}
		t.Fatalf("reboot claim while staging = %v, want errStageBusy", err)
	}
	releaseStageLock(staging)

	reboot, err := claimReboot(c, &statuses)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseStageLock(reboot)
	if staging, err := acquireStageLock(lockPath); !errors.Is(err, errStageBusy) {
		if staging != nil {
			releaseStageLock(staging)
		}
		t.Fatalf("stage claim during reboot = %v, want errStageBusy", err)
	}
}

type feedStats struct {
	checks    atomic.Int32
	artifacts atomic.Int32
}

// setupFeed serves a signed feed (root -> signing-cert -> manifest) advertising v2.
// publish replaces it with another signed release for feed-race tests.
func setupFeed(t *testing.T) (feed string, rootPubBytes []byte, stats *feedStats, publish func(string, string, string)) {
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
	rootfsHT, kcSig := write("rootfs.hash", 512), write("kc.bin.sig", 64)
	rootPriv, rootPubPath := filepath.Join(dir, "root.key"), filepath.Join(dir, "root.pub")
	if err := signing.GenerateKeyFiles(rootPriv, rootPubPath); err != nil {
		t.Fatal(err)
	}
	cert, signingKey := filepath.Join(dir, "signing-cert.json"), filepath.Join(dir, "signing.key")
	if err := signing.IssueCert(rootPriv, cert, signingKey, 1, 365*24*time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	stats = &feedStats{}
	files := http.FileServer(http.Dir(dir))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case "signing-cert.json", "signing-cert.json.sig", "manifest.json", "manifest.json.sig":
			stats.checks.Add(1)
		default:
			stats.artifacts.Add(1)
		}
		files.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	manifest := filepath.Join(dir, "manifest.json")
	publish = func(version, productVersion, productBuild string) {
		t.Helper()
		if _, err := signing.BuildManifest(manifest, signing.ReleaseSpec{
			Version: version, MinVersion: "v1",
			ProductName: "Sinty OS Event Horizon", ProductVersion: productVersion, ProductBuild: productBuild,
			RootFSFile: rootfs, RootFSURL: srv.URL + "/rootfs.bin",
			RootFSVerityHash:   "deadbeefcafe",
			RootFSHashTreeFile: rootfsHT, RootFSHashTreeURL: srv.URL + "/rootfs.hash",
			KernelcacheFile: kc, KernelcacheURL: srv.URL + "/kc.bin",
			KernelcacheSigFile: kcSig, KernelcacheSigURL: srv.URL + "/kc.bin.sig",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := signing.SignManifest(signingKey, manifest); err != nil {
			t.Fatal(err)
		}
	}
	publish("v2", "26", "26A010")
	b, err := os.ReadFile(rootPubPath)
	if err != nil {
		t.Fatal(err)
	}
	return srv.URL, b, stats, publish
}

func TestPollOnceChecksWithoutDownload(t *testing.T) {
	feed, rp, stats, _ := setupFeed(t)
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
		firmwareDir: filepath.Join(work, "firmware"), stageLock: filepath.Join(work, "stage.lock"),
	}

	st := pollOnce(c)
	if st.State != "available" || st.ProductName != "Sinty OS Event Horizon" || st.ProductVersion != "26" || st.ProductBuild != "26A010" {
		t.Fatalf("poll status = %+v, want available public 26 build 26A010", st)
	}
	if len(st.manifestSHA256) != 64 {
		t.Fatalf("poll did not retain checked manifest digest: %q", st.manifestSHA256)
	}
	if _, err := os.Stat(filepath.Join(c.rootfsDir, "rootfs-next.erofs")); err == nil {
		t.Fatal("poll must not stage the rootfs")
	}
	if got := stats.artifacts.Load(); got != 0 {
		t.Fatalf("poll fetched %d artifacts, want 0", got)
	}
}

func TestStartupCheckRetriesNetworkErrorsWithoutDownloading(t *testing.T) {
	feed, rp, stats, _ := setupFeed(t)
	old := rootPub
	rootPub = rp
	t.Cleanup(func() { rootPub = old })

	var certRequests atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/signing-cert.json" && certRequests.Add(1) <= 2 {
			http.Error(w, "network unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Redirect(w, r, feed+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	t.Cleanup(flaky.Close)

	work := t.TempDir()
	statuses := statusStore{statePath: filepath.Join(work, "status.json")}
	startupCheck(cfg{feed: flaky.URL, current: "v1"}, &statuses, time.Millisecond)

	status := statuses.get()
	if status.State != "available" || status.ProductVersion != "26" {
		t.Fatalf("startup retry status = %+v, want available 26", status)
	}
	if got := certRequests.Load(); got != 3 {
		t.Fatalf("startup signing-cert requests = %d, want 3", got)
	}
	if got := stats.artifacts.Load(); got != 0 {
		t.Fatalf("startup retry fetched %d artifacts, want 0", got)
	}
}

func TestStartupCheckRetriesNetworkErrorBehindReadyStatus(t *testing.T) {
	feed, rp, stats, _ := setupFeed(t)
	old := rootPub
	rootPub = rp
	t.Cleanup(func() { rootPub = old })

	var certRequests atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/signing-cert.json" && certRequests.Add(1) <= 2 {
			http.Error(w, "network unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Redirect(w, r, feed+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	t.Cleanup(flaky.Close)

	statePath := filepath.Join(t.TempDir(), "status.json")
	if err := writeState(statePath, Status{State: "ready", Current: "v1", Latest: "v2"}); err != nil {
		t.Fatal(err)
	}
	statuses := statusStore{statePath: statePath}
	startupCheck(cfg{feed: flaky.URL, current: "v1"}, &statuses, time.Millisecond)

	if got := certRequests.Load(); got != 3 {
		t.Fatalf("startup requests behind ready status = %d, want 3", got)
	}
	if status := statuses.get(); status.State != "ready" {
		t.Fatalf("startup replaced ready status: %+v", status)
	}
	if got := stats.artifacts.Load(); got != 0 {
		t.Fatalf("startup retry fetched %d artifacts, want 0", got)
	}
}

func TestStartupCheckDoesNotRetrySignatureFailure(t *testing.T) {
	feed, rp, stats, _ := setupFeed(t)
	old := rootPub
	rootPub = rp
	t.Cleanup(func() { rootPub = old })

	var certRequests atomic.Int32
	invalid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/signing-cert.json" {
			certRequests.Add(1)
		}
		if r.URL.Path == "/manifest.json.sig" {
			w.Write([]byte("invalid signature"))
			return
		}
		http.Redirect(w, r, feed+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	t.Cleanup(invalid.Close)

	statuses := statusStore{statePath: filepath.Join(t.TempDir(), "status.json")}
	startupCheck(cfg{feed: invalid.URL, current: "v1"}, &statuses, time.Millisecond)

	if got := certRequests.Load(); got != 1 {
		t.Fatalf("signature failure startup requests = %d, want 1", got)
	}
	if status := statuses.get(); status.State != "error" || !strings.Contains(status.Error, "manifest signature invalid") {
		t.Fatalf("signature failure status = %+v", status)
	}
	if got := stats.artifacts.Load(); got != 0 {
		t.Fatalf("signature failure fetched %d artifacts, want 0", got)
	}
}

func TestListenSocketRejectsNonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "updated.sock")
	if err := os.WriteFile(path, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenSocket(path); err == nil {
		ln.Close()
		t.Fatal("regular file accepted as stale socket")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "keep" {
		t.Fatalf("regular file changed: body=%q err=%v", b, err)
	}
}

func TestUnixServerChecksThenDownloadsOnlyOnPost(t *testing.T) {
	feed, rp, stats, _ := setupFeed(t)
	old := rootPub
	rootPub = rp
	t.Cleanup(func() { rootPub = old })

	work := t.TempDir()
	wal := filepath.Join(work, "deployment.json")
	if err := deployment.New("dev", "v1").Save(wal); err != nil {
		t.Fatal(err)
	}
	c := cfg{
		feed: feed, current: "v1", state: filepath.Join(work, "run", "updated", "status.json"),
		sock: filepath.Join(work, "run", "updated.sock"), wal: wal,
		rootfsDir: filepath.Join(work, "rootfs"), espDir: filepath.Join(work, "esp"),
		firmwareDir: filepath.Join(work, "firmware"), stageLock: filepath.Join(work, "run", "updated-stage.lock"),
	}
	ln, err := listenSocket(c.sock)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(c.sock)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket missing before startup check: mode=%v err=%v", info, err)
	}
	if got := stats.checks.Load(); got != 0 {
		t.Fatalf("feed check started before socket bind: requests=%d", got)
	}

	srv := newUpdateServer(c)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	})

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", c.sock)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request := func(method, path string) (Status, *http.Response) {
		t.Helper()
		req, err := http.NewRequest(method, "http://updated"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var status Status
		if resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
				resp.Body.Close()
				t.Fatal(err)
			}
		}
		resp.Body.Close()
		return status, resp
	}
	waitState := func(want string) Status {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			status, resp := request(http.MethodGet, "/status")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET /status = %d", resp.StatusCode)
			}
			if status.State == want {
				return status
			}
			if time.Now().After(deadline) {
				t.Fatalf("status = %+v, want %s", status, want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	available := waitState("available")
	if available.ProductName != "Sinty OS Event Horizon" || available.ProductVersion != "26" || available.ProductBuild != "26A010" {
		t.Fatalf("startup check lost product metadata: %+v", available)
	}
	if len(available.ConsentToken) != 64 {
		t.Fatalf("startup check consent token = %q", available.ConsentToken)
	}
	if got := stats.artifacts.Load(); got != 0 {
		t.Fatalf("startup check fetched %d artifacts, want 0", got)
	}
	if _, resp := request(http.MethodGet, "/check"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /check = %d", resp.StatusCode)
	}
	if got := stats.artifacts.Load(); got != 0 {
		t.Fatalf("periodic check fetched %d artifacts, want 0", got)
	}
	for _, endpoint := range []string{"/status", "/check"} {
		if _, resp := request(http.MethodPost, endpoint); resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodGet {
			t.Fatalf("POST %s = %d Allow=%q", endpoint, resp.StatusCode, resp.Header.Get("Allow"))
		}
	}
	if _, resp := request(http.MethodGet, "/download"); resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
		t.Fatalf("GET /download = %d Allow=%q", resp.StatusCode, resp.Header.Get("Allow"))
	}
	if _, resp := request(http.MethodGet, "/reboot"); resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
		t.Fatalf("GET /reboot = %d Allow=%q", resp.StatusCode, resp.Header.Get("Allow"))
	}
	if got := stats.artifacts.Load(); got != 0 {
		t.Fatalf("GET /download fetched %d artifacts, want 0", got)
	}
	if _, resp := request(http.MethodPost, "/download"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /download without consent = %d", resp.StatusCode)
	}
	if _, resp := request(http.MethodPost, "/download?junk=%ZZ&token="+available.ConsentToken); resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /download with malformed query = %d", resp.StatusCode)
	}
	if got := stats.artifacts.Load(); got != 0 {
		t.Fatalf("tokenless POST /download fetched %d artifacts, want 0", got)
	}
	if status, resp := request(http.MethodPost, "/download?token="+available.ConsentToken); resp.StatusCode != http.StatusOK || (status.State != "downloading" && status.State != "ready") {
		t.Fatalf("POST /download = %d status=%+v", resp.StatusCode, status)
	}
	ready := waitState("ready")
	if ready.Percent != 100 || ready.ProductVersion != "26" || ready.ProductBuild != "26A010" {
		t.Fatalf("ready status = %+v", ready)
	}
	if got := stats.artifacts.Load(); got != 4 {
		t.Fatalf("POST /download fetched %d artifacts, want 4", got)
	}
	if status, resp := request(http.MethodGet, "/check"); resp.StatusCode != http.StatusOK || status.State != "ready" {
		t.Fatalf("check after download = %d status=%+v, want ready", resp.StatusCode, status)
	}
	if got := stats.artifacts.Load(); got != 4 {
		t.Fatalf("check after download fetched %d artifacts, want 4 total", got)
	}
	for _, path := range []string{
		filepath.Join(c.rootfsDir, "rootfs-next.erofs"),
		filepath.Join(c.rootfsDir, "rootfs-next.hash"),
		filepath.Join(c.espDir, "kernelcache-next.efi"),
		filepath.Join(c.espDir, "kernelcache-next.efi.sig"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("download did not stage %s: %v", path, err)
		}
	}
}

func TestDownloadRejectsFeedChangedSinceCheck(t *testing.T) {
	feed, rp, stats, publish := setupFeed(t)
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
		firmwareDir: filepath.Join(work, "firmware"), stageLock: filepath.Join(work, "stage.lock"),
	}
	server := httptest.NewServer(newUpdateServer(c).Handler)
	t.Cleanup(server.Close)

	request := func(method, path string) Status {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s = %d", method, path, resp.StatusCode)
		}
		var status Status
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	waitState := func(want string) Status {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			status := request(http.MethodGet, "/status")
			if status.State == want {
				return status
			}
			if time.Now().After(deadline) {
				t.Fatalf("status = %+v, want %s", status, want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	approved := waitState("available")
	if approved.Latest != "v2" || approved.ProductVersion != "26" {
		t.Fatalf("checked status = %+v, want internal v2 public 26", approved)
	}
	publish("v3", "26.1", "26A011")
	if err := writeState(c.state, pollOnce(c)); err != nil {
		t.Fatal(err)
	}
	request(http.MethodPost, "/download?token="+approved.ConsentToken)
	failed := waitState("error")
	if !strings.Contains(failed.Error, "manifest changed since update check") {
		t.Fatalf("changed feed error = %q", failed.Error)
	}
	if got := stats.artifacts.Load(); got != 0 {
		t.Fatalf("changed feed fetched %d artifacts before renewed consent, want 0", got)
	}
	d, err := deployment.Load(wal)
	if err != nil {
		t.Fatal(err)
	}
	if d.HasPending() {
		t.Fatalf("changed feed staged an unapproved release: %+v", d.RootFS)
	}

	checked := request(http.MethodGet, "/check")
	if checked.State != "available" || checked.Latest != "v3" || checked.ProductVersion != "26.1" || checked.ProductBuild != "26A011" {
		t.Fatalf("renewed check = %+v, want internal v3 public 26.1 build 26A011", checked)
	}
	request(http.MethodPost, "/download?token="+checked.ConsentToken)
	ready := waitState("ready")
	if ready.Latest != "v3" || ready.ProductVersion != "26.1" || ready.ProductBuild != "26A011" {
		t.Fatalf("ready status = %+v, want staged internal v3 public 26.1 build 26A011", ready)
	}
}
