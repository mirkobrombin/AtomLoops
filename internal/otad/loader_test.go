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
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

type loaderFeed struct {
	base     string
	rootPub  []byte
	signPriv ed25519.PrivateKey
	cert     []byte
	certSig  []byte
}

func newLoaderFeed(t *testing.T, version int, image []byte, imageSig []byte) loaderFeed {
	t.Helper()
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
	if imageSig == nil {
		imageSig = ed25519.Sign(signPriv, image)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	m := Manifest{
		Version:         "v2",
		MinVersion:      "v1",
		RootFSURL:       srv.URL + "/rootfs",
		RootFSHash:      h([]byte("rootfs")),
		KernelcacheURL:  srv.URL + "/kernelcache",
		KernelcacheHash: h([]byte("kernelcache")),
		LoaderVersion:   version,
		LoaderURL:       srv.URL + "/loader",
		LoaderHash:      h(image),
		LoaderSigURL:    srv.URL + "/loader-sig",
		LoaderSigHash:   h(imageSig),
	}
	mData, _ := json.Marshal(m)
	mSig := ed25519.Sign(signPriv, mData)
	mux.HandleFunc("/loader", func(w http.ResponseWriter, r *http.Request) { w.Write(image) })
	mux.HandleFunc("/loader-sig", func(w http.ResponseWriter, r *http.Request) { w.Write(imageSig) })
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mData) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(mSig) })
	mux.HandleFunc("/signing-cert.json", func(w http.ResponseWriter, r *http.Request) { w.Write(certBytes) })
	mux.HandleFunc("/signing-cert.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(certSig) })
	return loaderFeed{base: srv.URL, rootPub: rootPub, signPriv: signPriv, cert: certBytes, certSig: certSig}
}

func loaderImage(version string) []byte {
	return []byte("MZ fake loader body " + loaderMarker + version + "; tail")
}

func loaderDirs(t *testing.T, installed []byte) StageDirs {
	t.Helper()
	efi := filepath.Join(t.TempDir(), "EFI")
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(efi, "atom")}
	for _, d := range []string{dirs.ESP, filepath.Join(efi, "BOOT"), dirs.Rootfs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(efi, "BOOT", "BOOTX64.EFI"), installed, 0o644); err != nil {
		t.Fatal(err)
	}
	return dirs
}

func readFileT(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoaderVersionOf(t *testing.T) {
	if v := LoaderVersionOf([]byte("old loader without marker")); v != 1 {
		t.Errorf("unmarked loader = %d, want 1", v)
	}
	if v := LoaderVersionOf(loaderImage("7")); v != 7 {
		t.Errorf("marked loader = %d, want 7", v)
	}
}

func TestLoaderStageInstallCycle(t *testing.T) {
	old := []byte("MZ old loader")
	img := loaderImage("2")
	feed := newLoaderFeed(t, 2, img, nil)
	dirs := loaderDirs(t, old)
	wal := e2eWAL(t)

	msg, err := StageLoader(context.Background(), wal, feed.base+"/manifest.json", "", feed.rootPub, dirs, false)
	if err != nil {
		t.Fatalf("StageLoader: %v", err)
	}
	if !strings.Contains(msg, "staged") {
		t.Fatalf("StageLoader message = %q", msg)
	}
	if got := readFileT(t, filepath.Join(dirs.ESP, "kernelcache-next.efi")); got != string(img) {
		t.Fatal("candidate not written to the trial slot")
	}
	bs, err := ReadBootState(filepath.Join(dirs.ESP, "boot-state"))
	if err != nil || bs.Target != "next" || !bs.Trial || bs.Attempts != 1 {
		t.Fatalf("boot-state = %+v, %v", bs, err)
	}
	if st := ReadLoaderStatus(dirs); st.Installed != 1 || st.Candidate != 2 {
		t.Fatalf("status before boot = %+v", st)
	}

	if err := os.WriteFile(filepath.Join(dirs.ESP, loaderRanFile), []byte("version=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	msg, err = BootSuccess(wal, t.TempDir(), nil, dirs)
	if err != nil {
		t.Fatalf("BootSuccess: %v", err)
	}
	if !strings.Contains(msg, "installed") {
		t.Fatalf("BootSuccess message = %q", msg)
	}
	if got := readFileT(t, loaderBootPath(dirs)); got != string(img) {
		t.Fatal("candidate not installed as the boot loader")
	}
	if got := readFileT(t, filepath.Join(dirs.ESP, loaderPrevFile)); got != string(old) {
		t.Fatal("previous loader not kept")
	}
	if st := ReadLoaderStatus(dirs); st.Installed != 2 || st.Candidate != 0 || st.Failed != 0 {
		t.Fatalf("status after install = %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dirs.ESP, "kernelcache-next.efi")); err == nil {
		t.Fatal("trial slot not cleaned after install")
	}
	bs, _ = ReadBootState(filepath.Join(dirs.ESP, "boot-state"))
	if bs.Target != "active" {
		t.Fatalf("boot-state after install = %+v", bs)
	}
}

func TestLoaderThatDidNotStartIsNotInstalled(t *testing.T) {
	old := []byte("MZ old loader")
	feed := newLoaderFeed(t, 2, loaderImage("2"), nil)
	dirs := loaderDirs(t, old)
	wal := e2eWAL(t)
	if _, err := StageLoader(context.Background(), wal, feed.base+"/manifest.json", "", feed.rootPub, dirs, false); err != nil {
		t.Fatalf("StageLoader: %v", err)
	}
	msg, err := BootSuccess(wal, t.TempDir(), nil, dirs)
	if err != nil {
		t.Fatalf("BootSuccess: %v", err)
	}
	if !strings.Contains(msg, "did not start") {
		t.Fatalf("BootSuccess message = %q", msg)
	}
	if got := readFileT(t, loaderBootPath(dirs)); got != string(old) {
		t.Fatal("a loader that never ran replaced the installed one")
	}
	if st := ReadLoaderStatus(dirs); st.Failed != 2 || st.Candidate != 0 {
		t.Fatalf("status after failure = %+v", st)
	}
	if _, err := StageLoader(context.Background(), wal, feed.base+"/manifest.json", "", feed.rootPub, dirs, false); err == nil {
		t.Fatal("a failed loader version was staged again without being asked")
	}
	if _, err := StageLoader(context.Background(), wal, feed.base+"/manifest.json", "", feed.rootPub, dirs, true); err != nil {
		t.Fatalf("explicit retry refused: %v", err)
	}
}

func TestLoaderRefusals(t *testing.T) {
	t.Run("system update pending", func(t *testing.T) {
		feed := newLoaderFeed(t, 2, loaderImage("2"), nil)
		dirs := loaderDirs(t, []byte("MZ old"))
		wal := e2eWAL(t)
		d, _ := deployment.Load(wal)
		d.Deploy("v9")
		d.Save(wal)
		if _, err := StageLoader(context.Background(), wal, feed.base+"/manifest.json", "", feed.rootPub, dirs, false); err == nil {
			t.Fatal("loader staged over a pending system update")
		}
	})
	t.Run("version mismatch", func(t *testing.T) {
		feed := newLoaderFeed(t, 3, loaderImage("2"), nil)
		dirs := loaderDirs(t, []byte("MZ old"))
		if _, err := StageLoader(context.Background(), e2eWAL(t), feed.base+"/manifest.json", "", feed.rootPub, dirs, false); err == nil {
			t.Fatal("image with the wrong embedded version was staged")
		}
	})
	t.Run("bad signature", func(t *testing.T) {
		feed := newLoaderFeed(t, 2, loaderImage("2"), make([]byte, 64))
		dirs := loaderDirs(t, []byte("MZ old"))
		if _, err := StageLoader(context.Background(), e2eWAL(t), feed.base+"/manifest.json", "", feed.rootPub, dirs, false); err == nil {
			t.Fatal("loader with an invalid signature was staged")
		}
		if _, err := os.Stat(filepath.Join(dirs.ESP, "kernelcache-next.efi")); err == nil {
			t.Fatal("unsigned image left in the trial slot")
		}
	})
	t.Run("already installed", func(t *testing.T) {
		feed := newLoaderFeed(t, 2, loaderImage("2"), nil)
		dirs := loaderDirs(t, loaderImage("2"))
		msg, err := StageLoader(context.Background(), e2eWAL(t), feed.base+"/manifest.json", "", feed.rootPub, dirs, false)
		if err != nil || !strings.Contains(msg, "already installed") {
			t.Fatalf("StageLoader = %q, %v", msg, err)
		}
	})
}

func TestRepairLoader(t *testing.T) {
	img := loaderImage("2")
	feed := newLoaderFeed(t, 2, img, nil)
	dirs := loaderDirs(t, []byte("MZ broken"))
	os.WriteFile(filepath.Join(dirs.ESP, "signing-cert.json"), feed.cert, 0o644)
	os.WriteFile(filepath.Join(dirs.ESP, "signing-cert.json.sig"), feed.certSig, 0o644)
	if _, err := RepairLoader(dirs, img, make([]byte, 64), feed.rootPub); err == nil {
		t.Fatal("repair accepted an unsigned loader")
	}
	if _, err := RepairLoader(dirs, img, ed25519.Sign(feed.signPriv, img), feed.rootPub); err != nil {
		t.Fatalf("RepairLoader: %v", err)
	}
	if got := readFileT(t, loaderBootPath(dirs)); got != string(img) {
		t.Fatal("repair did not install the loader")
	}
}

func TestSystemStageCancelsLoaderCandidate(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	base, rootPub := signedFeedV2(t, "verity-v2")
	wal := e2eWAL(t)
	dirs := installedDirs(t)
	os.WriteFile(filepath.Join(dirs.ESP, loaderCandidateFile), []byte("version=2\nsha256=x\n"), 0o644)
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dirs.ESP, loaderCandidateFile)); err == nil {
		t.Fatal("system update left the loader candidate marker over its kernelcache")
	}
}

func TestReadBootInfo(t *testing.T) {
	dirs := loaderDirs(t, []byte("MZ old"))
	os.WriteFile(filepath.Join(dirs.ESP, "kernelcache-active.efi"), []byte("not a pe"), 0o644)
	os.WriteFile(filepath.Join(dirs.ESP, "kernelcache-next.efi"), loaderImage("2"), 0o644)
	os.WriteFile(filepath.Join(dirs.ESP, loaderCandidateFile), []byte("version=2\n"), 0o644)
	WriteBootState(filepath.Join(dirs.ESP, "boot-state"), BootState{Target: "next", Trial: true, Attempts: 1})
	info := ReadBootInfo(dirs)
	if info.Target != "next" || !info.Trial {
		t.Fatalf("boot info = %+v", info)
	}
	if info.Slots["active"] != "present" || info.Slots["next"] != "loader 2" {
		t.Fatalf("slots = %+v", info.Slots)
	}
	if _, ok := info.Slots["recovery"]; ok {
		t.Fatal("missing recovery slot reported")
	}
}

func TestKernelcacheVersionReadsRealImage(t *testing.T) {
	p := os.Getenv("ATOM_TEST_KERNELCACHE")
	if p == "" {
		t.Skip("ATOM_TEST_KERNELCACHE not set")
	}
	if v := KernelcacheVersion(p); !strings.HasPrefix(v, "v") {
		t.Fatalf("KernelcacheVersion = %q", v)
	}
}
