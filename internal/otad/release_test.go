package otad

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/trust"
)

func releaseServer(t *testing.T, arch string, corrupt string, families ...string) (string, []byte, map[string][]byte) {
	t.Helper()
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	cert, _ := json.Marshal(trust.SigningCert{
		Version: 1, SigningPubkey: base64.StdEncoding.EncodeToString(signPub),
		IssuedAt: "2026-01-01T00:00:00Z", NotAfter: "2099-01-01T00:00:00Z",
	})
	body := map[string][]byte{}
	for _, n := range []string{"rootfs.erofs", "rootfs.hash", "kernelcache.efi", "kernelcache.efi.sig",
		"loader.efi", "loader.efi.sig", "kernelcache-recovery.efi", "kernelcache-recovery.efi.sig"} {
		body[n] = []byte(arch + " " + n)
	}
	for _, f := range families {
		for _, n := range []string{"kernelcache." + f + ".efi", "kernelcache." + f + ".efi.sig"} {
			body[n] = []byte(arch + " " + n)
		}
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	for n, b := range body {
		served := b
		if n == corrupt {
			served = []byte("tampered")
		}
		mux.HandleFunc("/a/"+n, func(w http.ResponseWriter, r *http.Request) { w.Write(served) })
	}
	u := func(n string) string { return srv.URL + "/a/" + n }
	h := func(n string) string { return sha256hex(body[n]) }
	m := Manifest{
		Version: "v9", MinVersion: "v9", Arch: arch,
		RootFSURL: u("rootfs.erofs"), RootFSHash: h("rootfs.erofs"),
		RootFSHashTreeURL: u("rootfs.hash"), RootFSHashTreeHash: h("rootfs.hash"),
		KernelcacheURL: u("kernelcache.efi"), KernelcacheHash: h("kernelcache.efi"),
		KernelcacheSigURL: u("kernelcache.efi.sig"), KernelcacheSigHash: h("kernelcache.efi.sig"),
		LoaderVersion: 4, LoaderURL: u("loader.efi"), LoaderHash: h("loader.efi"),
		LoaderSigURL: u("loader.efi.sig"), LoaderSigHash: h("loader.efi.sig"),
		RecoveryVersion: 4, RecoveryURL: u("kernelcache-recovery.efi"), RecoveryHash: h("kernelcache-recovery.efi"),
		RecoverySigURL: u("kernelcache-recovery.efi.sig"), RecoverySigHash: h("kernelcache-recovery.efi.sig"),
	}
	for _, f := range families {
		kc := "kernelcache." + f + ".efi"
		m.KernelFamilies = append(m.KernelFamilies, KernelFamily{Name: f, URL: u(kc), Hash: h(kc), SigURL: u(kc + ".sig"), SigHash: h(kc + ".sig")})
	}
	mData, _ := json.Marshal(m)
	mSig := ed25519.Sign(signPriv, mData)
	certSig := ed25519.Sign(rootPriv, cert)
	mux.HandleFunc("/feed/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mData) })
	mux.HandleFunc("/feed/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(mSig) })
	mux.HandleFunc("/feed/signing-cert.json", func(w http.ResponseWriter, r *http.Request) { w.Write(cert) })
	mux.HandleFunc("/feed/signing-cert.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(certSig) })
	return srv.URL + "/feed", rootPub, body
}

func TestFetchReleaseForAnotherArch(t *testing.T) {
	feed, rootPub, body := releaseServer(t, "aarch64", "")
	dir := t.TempDir()
	var seen []string
	m, err := FetchRelease(context.Background(), feed, "aarch64", rootPub, dir, func(i, n int, name string) { seen = append(seen, name) })
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "v9" || m.Arch != "aarch64" {
		t.Fatalf("manifest %+v", m)
	}
	if seen[len(seen)-1] != "rootfs.erofs" {
		t.Fatalf("root image not last: %v", seen)
	}
	for n, want := range body {
		got, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s: %q %v", n, got, err)
		}
	}
	for _, n := range []string{"signing-cert.json", "signing-cert.json.sig"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFetchReleaseTakesOnlyThisBoardsKernel(t *testing.T) {
	feed, rootPub, body := releaseServer(t, "aarch64", "", "l4t", "rk")
	onBoard(t, "nvidia,p3768-0000+p3767-0005\x00nvidia,tegra234\x00")
	dir := t.TempDir()
	if _, err := FetchRelease(context.Background(), feed, "aarch64", rootPub, dir, nil); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"kernelcache.l4t.efi", "kernelcache.l4t.efi.sig"} {
		got, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil || string(got) != string(body[n]) {
			t.Fatalf("%s: %q %v", n, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "kernelcache.rk.efi")); !os.IsNotExist(err) {
		t.Fatalf("another board's kernel was downloaded: %v", err)
	}
	onBoard(t, "linux,dummy-virt\x00")
	plain := t.TempDir()
	if _, err := FetchRelease(context.Background(), feed, "aarch64", rootPub, plain, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(plain, "kernelcache.l4t.efi")); !os.IsNotExist(err) {
		t.Fatalf("a family kernel was downloaded on a plain board: %v", err)
	}
}

func TestFetchReleaseRefusesTamperedFamilyKernel(t *testing.T) {
	feed, rootPub, _ := releaseServer(t, "aarch64", "kernelcache.l4t.efi", "l4t")
	onBoard(t, "nvidia,tegra234\x00")
	if _, err := FetchRelease(context.Background(), feed, "aarch64", rootPub, t.TempDir(), nil); err == nil {
		t.Fatal("tampered family kernel accepted")
	}
}

func TestFetchReleaseRefusesWrongArch(t *testing.T) {
	feed, rootPub, _ := releaseServer(t, "x86_64", "")
	_, err := FetchRelease(context.Background(), feed, "aarch64", rootPub, t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "built for x86_64") {
		t.Fatalf("x86_64 release accepted as aarch64: %v", err)
	}
}

func TestFetchReleaseRefusesTamperedFile(t *testing.T) {
	feed, rootPub, _ := releaseServer(t, "aarch64", "loader.efi")
	dir := t.TempDir()
	_, err := FetchRelease(context.Background(), feed, "aarch64", rootPub, dir, nil)
	if err == nil || !strings.Contains(err.Error(), "loader.efi") {
		t.Fatalf("tampered loader accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "loader.efi")); !os.IsNotExist(err) {
		t.Fatalf("tampered loader left on disk: %v", err)
	}
}
