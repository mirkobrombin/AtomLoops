package otad

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

var OptInPath = "/var/lib/atom/firmware-optin"

func OptedIn(path string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if name := strings.TrimSpace(line); name != "" {
			out[name] = true
		}
	}
	return out
}

func (f FirmwareBundleSpec) Wanted(opted map[string]bool) bool {
	return !f.OptIn || opted[f.Name]
}

func SetOptIn(path, name string, on bool) error {
	if name == "" || strings.ContainsAny(name, "/\n") {
		return fmt.Errorf("opt-in: invalid bundle name %q", name)
	}
	set := OptedIn(path)
	if on {
		set[name] = true
	} else {
		delete(set, name)
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".new"
	data := strings.Join(names, "\n")
	if data != "" {
		data += "\n"
	}
	if err := os.WriteFile(tmp, []byte(data), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func StageFirmwareBundle(ctx context.Context, walPath, manifestURL string, rootPub []byte, dirs StageDirs, name string) (string, error) {
	if dirs.Firmware == "" {
		return "", fmt.Errorf("stage firmware: no firmware dir configured")
	}
	work, err := os.MkdirTemp("", "atomd-fw-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	vm, err := fetchVerifiedManifest(ctx, work, manifestURL, "", rootPub, "")
	if err != nil {
		return "", err
	}
	var fw *FirmwareBundleSpec
	for _, b := range vm.manifest.FirmwareBundleList() {
		if b.Name == name {
			b := b
			fw = &b
		}
	}
	if fw == nil {
		return "", fmt.Errorf("stage firmware: the update feed offers no bundle %q", name)
	}
	if !fw.MatchesHardware(DetectGPUChips(""), RunningKernel()) {
		return "", fmt.Errorf("stage firmware: bundle %q does not fit this computer or its running kernel; update the system first", name)
	}
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	if b, ok := d.Firmware.Bundles[name]; ok && fw.Version <= b.MinVersion {
		return "", fmt.Errorf("stage firmware: bundle %q v%d is already installed", name, fw.Version)
	}
	if err := stageBundle(ctx, dirs, *fw, vm.data, vm.sig, vm.cert, vm.certSig); err != nil {
		return "", err
	}
	if !d.DeployFirmware(fw.Name, fw.Version, fw.VerityHash) {
		return "", fmt.Errorf("stage firmware: bundle %q v%d is below its anti-rollback floor", name, fw.Version)
	}
	if err := d.Save(walPath); err != nil {
		return "", err
	}
	for _, dir := range []string{dirs.Firmware, filepath.Dir(walPath)} {
		if err := commitDir(dir); err != nil {
			return "", err
		}
	}
	if err := ActivateFirmwareSlot(filepath.Join(dirs.Firmware, fw.Name)); err != nil {
		return "", err
	}
	return fmt.Sprintf("staged firmware %s v%d; restart to use it", fw.Name, fw.Version), nil
}

func RemoveFirmwareBundle(walPath string, dirs StageDirs, name string) error {
	if name == "" || strings.ContainsAny(name, "/\n") || name == "." || name == ".." {
		return fmt.Errorf("remove firmware: invalid bundle name %q", name)
	}
	d, err := deployment.Load(walPath)
	if err != nil {
		return err
	}
	delete(d.Firmware.Bundles, name)
	if err := d.Save(walPath); err != nil {
		return err
	}
	if dirs.Firmware != "" {
		if err := os.RemoveAll(filepath.Join(dirs.Firmware, name)); err != nil {
			return err
		}
		if err := commitDir(dirs.Firmware); err != nil {
			return err
		}
	}
	return commitDir(filepath.Dir(walPath))
}

type OptInOffer struct {
	Name             string `json:"name"`
	Version          int    `json:"version"`
	Chosen           bool   `json:"chosen"`
	InstalledVersion int    `json:"installed_version"`
	Pending          bool   `json:"pending"`
	FitsKernel       bool   `json:"fits_kernel"`
}

func OptInOffers(ctx context.Context, walPath, manifestURL string, rootPub []byte) ([]OptInOffer, error) {
	work, err := os.MkdirTemp("", "atomd-offers-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	vm, err := fetchVerifiedManifest(ctx, work, manifestURL, "", rootPub, "")
	if err != nil {
		return nil, err
	}
	return optInOffers(vm.manifest, walPath, DetectGPUChips(""), RunningKernel(), OptedIn(OptInPath))
}

func optInOffers(m Manifest, walPath string, chips []string, kernel string, opted map[string]bool) ([]OptInOffer, error) {
	d, err := deployment.Load(walPath)
	if err != nil {
		return nil, err
	}
	out := []OptInOffer{}
	for _, b := range m.FirmwareBundleList() {
		if !b.OptIn || !b.MatchesHardware(chips, "") {
			continue
		}
		o := OptInOffer{Name: b.Name, Version: b.Version, Chosen: opted[b.Name], FitsKernel: b.MatchesHardware(chips, kernel)}
		if st, ok := d.Firmware.Bundles[b.Name]; ok {
			o.InstalledVersion = st.CurrentVersion
			o.Pending = st.PendingVersion != 0
		}
		out = append(out, o)
	}
	return out, nil
}
