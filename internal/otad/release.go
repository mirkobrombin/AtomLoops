package otad

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReleaseFile names one artifact of a release written by FetchRelease.
type ReleaseFile struct {
	Name, URL, Hash string
}

// ReleaseFiles lists what a bootable copy of the release needs, in download order:
// the small boot files first, the root image last.
func ReleaseFiles(m Manifest) ([]ReleaseFile, error) {
	switch {
	case m.RootFSHashTreeURL == "":
		return nil, fmt.Errorf("release %s carries no rootfs hash tree", m.Version)
	case m.KernelcacheSigURL == "":
		return nil, fmt.Errorf("release %s carries no kernelcache signature", m.Version)
	case m.LoaderURL == "" || m.LoaderSigURL == "":
		return nil, fmt.Errorf("release %s carries no boot loader", m.Version)
	}
	files := []ReleaseFile{
		{"kernelcache.efi.sig", m.KernelcacheSigURL, m.KernelcacheSigHash},
		{"loader.efi.sig", m.LoaderSigURL, m.LoaderSigHash},
		{"loader.efi", m.LoaderURL, m.LoaderHash},
		{"kernelcache.efi", m.KernelcacheURL, m.KernelcacheHash},
	}
	if m.RecoveryURL != "" && m.RecoverySigURL != "" {
		files = append(files,
			ReleaseFile{"kernelcache-recovery.efi.sig", m.RecoverySigURL, m.RecoverySigHash},
			ReleaseFile{"kernelcache-recovery.efi", m.RecoveryURL, m.RecoveryHash})
	}
	return append(files,
		ReleaseFile{"rootfs.hash", m.RootFSHashTreeURL, m.RootFSHashTreeHash},
		ReleaseFile{"rootfs.erofs", m.RootFSURL, m.RootFSHash}), nil
}

// FetchRelease downloads the release a feed currently offers for arch into dir and
// verifies every file against the signed manifest. The signing certificate is kept
// beside the files because the boot partition carries it. onFile is told which file
// starts downloading; ctx may carry a ProgressFunc for the bytes.
func FetchRelease(ctx context.Context, feed, arch string, rootPub []byte, dir string, onFile func(i, n int, name string)) (Manifest, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Manifest{}, err
	}
	vm, err := fetchVerifiedManifestFor(ctx, dir, strings.TrimRight(feed, "/")+"/manifest.json", "", rootPub, "", arch)
	if err != nil {
		return Manifest{}, err
	}
	files, err := ReleaseFiles(vm.manifest)
	if err != nil {
		return Manifest{}, err
	}
	for i, f := range files {
		if f.Hash == "" {
			return Manifest{}, fmt.Errorf("release %s: no hash for %s", vm.manifest.Version, f.Name)
		}
		if onFile != nil {
			onFile(i, len(files), f.Name)
		}
		p := filepath.Join(dir, f.Name)
		if VerifySHA256(p, f.Hash) == nil {
			continue
		}
		if _, err := FetchTo(ctx, f.URL, p); err != nil {
			return Manifest{}, err
		}
		if err := VerifySHA256(p, f.Hash); err != nil {
			os.Remove(p)
			return Manifest{}, fmt.Errorf("%s: %w", f.Name, err)
		}
	}
	return vm.manifest, nil
}
