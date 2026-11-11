package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/otad"
)

func firmwareCall(t *testing.T, mux *http.ServeMux, method, path string) (optionalFirmware, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	var st optionalFirmware
	if rec.Code != http.StatusMethodNotAllowed {
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body.String())
		}
	}
	return st, rec.Code
}

func TestOptionalFirmwareEndpoints(t *testing.T) {
	c := loaderTestCfg(t)
	feed := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(feed.Close)
	c.feed = feed.URL
	c.firmwareDir = filepath.Join(t.TempDir(), "firmware")
	old := otad.OptInPath
	otad.OptInPath = filepath.Join(t.TempDir(), "firmware-optin")
	t.Cleanup(func() { otad.OptInPath = old })

	d, _ := deployment.Load(c.wal)
	d.Firmware.Bundle("extra").CurrentVersion = 2
	if err := d.Save(c.wal); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(c.firmwareDir, "extra"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := otad.SetOptIn(otad.OptInPath, "extra", true); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	registerFirmwareHandlers(mux, c)

	if _, code := firmwareCall(t, mux, http.MethodPost, "/firmware/optional"); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST list: %d", code)
	}
	if _, code := firmwareCall(t, mux, http.MethodGet, "/firmware/optional/enable?name=extra"); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET enable: %d", code)
	}
	st, code := firmwareCall(t, mux, http.MethodGet, "/firmware/optional")
	if code != http.StatusBadGateway || st.Error == "" || st.Bundles == nil {
		t.Fatalf("list with feed down: %d %+v", code, st)
	}
	st, code = firmwareCall(t, mux, http.MethodPost, "/firmware/optional/enable?name=other")
	if code != http.StatusConflict || st.Error == "" {
		t.Fatalf("enable with feed down: %d %+v", code, st)
	}
	if otad.OptedIn(otad.OptInPath)["other"] {
		t.Fatal("failed enable left the choice recorded")
	}
	if _, code = firmwareCall(t, mux, http.MethodPost, "/firmware/optional/disable?name=../x"); code != http.StatusConflict {
		t.Fatalf("disable with a bad name: %d", code)
	}
	st, code = firmwareCall(t, mux, http.MethodPost, "/firmware/optional/disable?name=extra")
	if code != http.StatusOK || st.Message == "" {
		t.Fatalf("disable: %d %+v", code, st)
	}
	if otad.OptedIn(otad.OptInPath)["extra"] {
		t.Fatal("choice still recorded")
	}
	d, _ = deployment.Load(c.wal)
	if _, ok := d.Firmware.Bundles["extra"]; ok {
		t.Fatal("bundle still in the WAL")
	}
	if _, err := os.Stat(filepath.Join(c.firmwareDir, "extra")); !os.IsNotExist(err) {
		t.Fatalf("bundle dir left: %v", err)
	}
}
