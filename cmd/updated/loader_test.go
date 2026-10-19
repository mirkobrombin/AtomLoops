package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func loaderTestCfg(t *testing.T) cfg {
	t.Helper()
	work := t.TempDir()
	esp := filepath.Join(work, "EFI", "atom")
	for _, d := range []string{esp, filepath.Join(work, "EFI", "BOOT")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, "EFI", "BOOT", "BOOTX64.EFI"), []byte("MZ old loader"), 0o644); err != nil {
		t.Fatal(err)
	}
	wal := filepath.Join(work, "deployment.json")
	if err := deployment.New("dev", "v1").Save(wal); err != nil {
		t.Fatal(err)
	}
	old := loaderAutoFlag
	loaderAutoFlag = filepath.Join(work, "loader-auto")
	t.Cleanup(func() { loaderAutoFlag = old })
	return cfg{current: "v1", wal: wal, espDir: esp, rootfsDir: filepath.Join(work, "rootfs"),
		stageLock: filepath.Join(work, "stage.lock")}
}

func loaderCall(t *testing.T, mux *http.ServeMux, method, path string) (loaderStatus, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	var st loaderStatus
	if rec.Code != http.StatusMethodNotAllowed {
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body.String())
		}
	}
	return st, rec.Code
}

func TestLoaderEndpoints(t *testing.T) {
	feed, rp, _, _ := setupFeed(t)
	old := rootPub
	rootPub = rp
	t.Cleanup(func() { rootPub = old })
	c := loaderTestCfg(t)
	c.feed = feed
	statuses := statusStore{}
	mux := http.NewServeMux()
	registerLoaderHandlers(mux, c, &statuses)

	st, code := loaderCall(t, mux, http.MethodGet, "/loader")
	if code != http.StatusOK || st.Installed != 1 || st.Auto {
		t.Fatalf("GET /loader = %d %+v", code, st)
	}
	if _, code := loaderCall(t, mux, http.MethodPost, "/loader"); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /loader = %d", code)
	}
	st, code = loaderCall(t, mux, http.MethodPost, "/loader/auto?enable=1")
	if code != http.StatusOK || !st.Auto {
		t.Fatalf("enable auto = %d %+v", code, st)
	}
	st, _ = loaderCall(t, mux, http.MethodPost, "/loader/auto?enable=0")
	if st.Auto {
		t.Fatal("auto still on after disabling")
	}
	st, code = loaderCall(t, mux, http.MethodPost, "/loader/update")
	if code != http.StatusConflict || st.Error == "" {
		t.Fatalf("update from a feed without a loader = %d %+v", code, st)
	}
	if _, err := os.Stat(filepath.Join(c.espDir, "kernelcache-next.efi")); err == nil {
		t.Fatal("failed loader update touched the trial slot")
	}
}

func TestAutoStageLoaderSkips(t *testing.T) {
	c := loaderTestCfg(t)
	c.feed = "http://127.0.0.1:1"
	staged := func() bool {
		_, err := os.Stat(filepath.Join(c.espDir, "loader-candidate"))
		return err == nil
	}
	maybeAutoStageLoader(c, Status{State: "idle", LoaderAvailable: 2})
	if staged() {
		t.Fatal("staged with auto off")
	}
	if err := setLoaderAuto(true); err != nil {
		t.Fatal(err)
	}
	for _, s := range []Status{
		{State: "available", LoaderAvailable: 2},
		{State: "ready", LoaderAvailable: 2},
		{State: "idle", LoaderAvailable: 1},
		{State: "idle"},
	} {
		maybeAutoStageLoader(c, s)
		if staged() {
			t.Fatalf("staged for %+v", s)
		}
	}
}
