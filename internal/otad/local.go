package otad

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

const fileScheme = "file://"

type localDirKey struct{}

var anchorFiles = []string{"manifest.json", "manifest.json.sig", "signing-cert.json", "signing-cert.json.sig"}

func copyLocal(ctx context.Context, src, tmp string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return 0, err
	}
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	var r io.Reader = in
	if cb, ok := ctx.Value(progressKey{}).(ProgressFunc); ok && cb != nil {
		r = &progressReader{r: in, total: st.Size(), cb: cb}
	}
	n, err := io.Copy(out, r)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}
	return n, nil
}

func localize(m Manifest, dir string) Manifest {
	at := func(url, name string) string {
		if url == "" {
			return ""
		}
		return fileScheme + filepath.Join(dir, name)
	}
	m.RootFSURL = at(m.RootFSURL, "rootfs.erofs")
	m.RootFSHashTreeURL = at(m.RootFSHashTreeURL, "rootfs.hash")
	m.KernelcacheURL = at(m.KernelcacheURL, "kernelcache.efi")
	m.KernelcacheSigURL = at(m.KernelcacheSigURL, "kernelcache.efi.sig")
	m.LoaderURL = at(m.LoaderURL, "loader.efi")
	m.LoaderSigURL = at(m.LoaderSigURL, "loader.efi.sig")
	m.RecoveryURL = at(m.RecoveryURL, "kernelcache-recovery.efi")
	m.RecoverySigURL = at(m.RecoverySigURL, "kernelcache-recovery.efi.sig")
	m.FirmwareURL = at(m.FirmwareURL, "firmware.img")
	m.FirmwareHashTreeURL = at(m.FirmwareHashTreeURL, "firmware.hash")
	bundles := slices.Clone(m.FirmwareBundles)
	for i := range bundles {
		bundles[i].URL = at(bundles[i].URL, filepath.Join("firmware", bundles[i].Name+".img"))
		bundles[i].HashTreeURL = at(bundles[i].HashTreeURL, filepath.Join("firmware", bundles[i].Name+".hash"))
	}
	m.FirmwareBundles = bundles
	return m
}

// StageFrom stages the release kept in dir, as written by ExportRelease or
// FetchRelease, exactly like an update from the feed: the same signature chain,
// hashes, architecture and anti-rollback checks, into the slots of dirs.
func StageFrom(ctx context.Context, walPath, dir string, rootPub []byte, dirs StageDirs) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	ctx = context.WithValue(ctx, localDirKey{}, abs)
	return stage(ctx, walPath, fileScheme+filepath.Join(abs, "manifest.json"), "", rootPub, dirs, "")
}

func anchorDir(rootfs, version string) string {
	return filepath.Join(rootfs, "release", version)
}

func saveAnchor(rootfs, version string, keep []string, files ...[]byte) error {
	if rootfs == "" || version == "" || strings.ContainsAny(version, "/\\") {
		return errors.New("release anchor: bad version")
	}
	dir := anchorDir(rootfs, version)
	tmp := dir + ".tmp"
	os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	for i, name := range anchorFiles {
		if err := os.WriteFile(filepath.Join(tmp, name), files[i], 0o644); err != nil {
			os.RemoveAll(tmp)
			return err
		}
	}
	os.RemoveAll(dir)
	if err := os.Rename(tmp, dir); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	entries, _ := os.ReadDir(filepath.Join(rootfs, "release"))
	for _, e := range entries {
		if e.Name() != version && !slices.Contains(keep, e.Name()) {
			os.RemoveAll(filepath.Join(rootfs, "release", e.Name()))
		}
	}
	return syncDir(filepath.Join(rootfs, "release"))
}

// InstalledVersion reports the version the slots of walPath run.
func InstalledVersion(walPath string) (string, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	if d.RootFS.Current == "" {
		return "", errors.New("no installed version recorded")
	}
	return d.RootFS.Current, nil
}

// ExportRelease writes into out a release of the version the slots of dirs run,
// so another machine can stage it without the network. The signed manifest kept
// when that version was staged is checked against rootPub, and every slot file
// against its hash, before it is offered. Slot files are linked, not copied.
func ExportRelease(walPath string, dirs StageDirs, rootPub []byte, out string) (Manifest, error) {
	version, err := InstalledVersion(walPath)
	if err != nil {
		return Manifest{}, err
	}
	anchor := anchorDir(dirs.Rootfs, version)
	data := make([][]byte, len(anchorFiles))
	for i, name := range anchorFiles {
		if data[i], err = os.ReadFile(filepath.Join(anchor, name)); err != nil {
			return Manifest{}, fmt.Errorf("no signed copy of release %s is kept here: %w", version, err)
		}
	}
	signingPub, _, err := trust.VerifyCert(data[2], data[3], rootPub, time.Now())
	if err != nil {
		return Manifest{}, fmt.Errorf("release %s: %w", version, err)
	}
	if len(signingPub) != ed25519.PublicKeySize || !trust.Verify(data[0], data[1], signingPub) {
		return Manifest{}, fmt.Errorf("release %s: manifest signature invalid", version)
	}
	m, err := ParseManifestFor(data[0], manifestArchOf(data[0]))
	if err != nil {
		return Manifest{}, err
	}
	if m.Version != version {
		return Manifest{}, fmt.Errorf("kept manifest is %s, the slots run %s", m.Version, version)
	}
	slots := []struct{ name, path, hash string }{
		{"rootfs.erofs", filepath.Join(dirs.Rootfs, "rootfs-active.erofs"), m.RootFSHash},
		{"rootfs.hash", filepath.Join(dirs.Rootfs, "rootfs-active.hash"), m.RootFSHashTreeHash},
		{"kernelcache.efi", filepath.Join(dirs.ESP, "kernelcache-active.efi"), m.KernelcacheHash},
		{"kernelcache.efi.sig", filepath.Join(dirs.ESP, "kernelcache-active.efi.sig"), m.KernelcacheSigHash},
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return Manifest{}, err
	}
	for _, s := range slots {
		if s.hash == "" {
			return Manifest{}, fmt.Errorf("release %s: no hash for %s", version, s.name)
		}
		if err := VerifySHA256(s.path, s.hash); err != nil {
			return Manifest{}, fmt.Errorf("%s does not match release %s: %w", s.name, version, err)
		}
		dst := filepath.Join(out, s.name)
		os.Remove(dst)
		if err := os.Symlink(s.path, dst); err != nil {
			return Manifest{}, err
		}
	}
	for i, name := range anchorFiles {
		if err := os.WriteFile(filepath.Join(out, name), data[i], 0o644); err != nil {
			return Manifest{}, err
		}
	}
	return m, nil
}

func manifestArchOf(data []byte) string {
	var probe struct {
		Arch string `json:"arch"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Arch(runtime.GOARCH)
	}
	return manifestArch(probe.Arch)
}
