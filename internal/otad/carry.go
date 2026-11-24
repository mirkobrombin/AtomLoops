package otad

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

type CarriedRelease struct {
	Manifest                 Manifest
	Data, Sig, Cert, CertSig []byte
	Path                     string
}

type ReleaseCarrier interface {
	FetchRootFS(ctx context.Context, r CarriedRelease, dest string) error
	Offer(r CarriedRelease)
}

var Carrier ReleaseCarrier

func fetchRootFS(ctx context.Context, vm *verifiedManifest, m Manifest, dest string, local bool) error {
	if Carrier != nil && !local {
		if _, _, err := m.RootFSBlockPlan(); err == nil {
			r := CarriedRelease{Manifest: m, Data: vm.data, Sig: vm.sig, Cert: vm.cert, CertSig: vm.certSig, Path: dest}
			err := Carrier.FetchRootFS(ctx, r, dest)
			if err == nil {
				return nil
			}
			log.Printf("otad: neighbours could not carry %s, the server takes over: %v", m.Version, err)
			os.Remove(dest)
		}
	}
	_, err := FetchTo(ctx, m.RootFSURL, dest)
	return err
}

func offerStaged(vm *verifiedManifest, m Manifest, path string) {
	if Carrier != nil {
		Carrier.Offer(CarriedRelease{Manifest: m, Data: vm.data, Sig: vm.sig, Cert: vm.cert, CertSig: vm.certSig, Path: path})
	}
}

func CarriedReleases(walPath string, dirs StageDirs) []CarriedRelease {
	d, err := deployment.Load(walPath)
	if err != nil {
		return nil
	}
	var out []CarriedRelease
	for _, s := range []struct{ version, image string }{
		{d.RootFS.Current, "rootfs-active.erofs"},
		{d.RootFS.Pending, "rootfs-next.erofs"},
	} {
		if s.version == "" {
			continue
		}
		dir := anchorDir(dirs.Rootfs, s.version)
		var files [4][]byte
		ok := true
		for i, name := range anchorFiles {
			if files[i], err = os.ReadFile(filepath.Join(dir, name)); err != nil {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		m, err := ParseManifest(files[0])
		if err != nil || m.Version != s.version {
			continue
		}
		out = append(out, CarriedRelease{Manifest: m, Data: files[0], Sig: files[1], Cert: files[2], CertSig: files[3],
			Path: filepath.Join(dirs.Rootfs, s.image)})
	}
	return out
}
