package otad

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

const (
	loaderCandidateFile = "loader-candidate"
	loaderRanFile       = "loader-ran"
	loaderFailedFile    = "loader-failed"
	loaderPrevFile      = "loader-prev.efi"
	loaderMarker        = "ATOM-LOADER-VERSION="
)

type LoaderStatus struct {
	Installed int    `json:"installed"`
	Candidate int    `json:"candidate,omitempty"`
	Failed    int    `json:"failed,omitempty"`
	Path      string `json:"path"`
}

func loaderBootPath(dirs StageDirs) string {
	return filepath.Join(filepath.Dir(dirs.ESP), "BOOT", "BOOTX64.EFI")
}

func LoaderVersionOf(image []byte) int {
	i := bytes.Index(image, []byte(loaderMarker))
	if i < 0 {
		return 1
	}
	rest := image[i+len(loaderMarker):]
	end := bytes.IndexByte(rest, ';')
	if end <= 0 || end > 16 {
		return 1
	}
	v, err := strconv.Atoi(string(rest[:end]))
	if err != nil || v < 1 {
		return 1
	}
	return v
}

func InstalledLoaderVersion(dirs StageDirs) int {
	b, err := os.ReadFile(loaderBootPath(dirs))
	if err != nil {
		return 0
	}
	return LoaderVersionOf(b)
}

func readKeyFile(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok {
			out[k] = v
		}
	}
	return out
}

func markerVersion(path string) int {
	v, _ := strconv.Atoi(readKeyFile(path)["version"])
	return v
}

func writeMarker(path string, fields ...string) error {
	if err := os.WriteFile(path, []byte(strings.Join(fields, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func ReadLoaderStatus(dirs StageDirs) LoaderStatus {
	return LoaderStatus{
		Installed: InstalledLoaderVersion(dirs),
		Candidate: markerVersion(filepath.Join(dirs.ESP, loaderCandidateFile)),
		Failed:    markerVersion(filepath.Join(dirs.ESP, loaderFailedFile)),
		Path:      loaderBootPath(dirs),
	}
}

func cancelLoaderCandidate(dirs StageDirs) {
	if dirs.ESP == "" {
		return
	}
	os.Remove(filepath.Join(dirs.ESP, loaderCandidateFile))
	os.Remove(filepath.Join(dirs.ESP, loaderRanFile))
}

func StageLoader(ctx context.Context, walPath, manifestURL, revocationURL string, rootPub []byte, dirs StageDirs, retryFailed bool) (string, error) {
	if dirs.ESP == "" {
		return "", errors.New("loader: no ESP configured")
	}
	d, err := deployment.Load(walPath)
	if err != nil {
		return "", err
	}
	if d.HasPending() {
		return "", errors.New("loader: a system update is waiting for a reboot, finish it first")
	}
	work, err := os.MkdirTemp("", "atomd-loader-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	vm, err := fetchVerifiedManifest(ctx, work, manifestURL, revocationURL, rootPub, "")
	if err != nil {
		return "", err
	}
	m := vm.manifest
	if m.LoaderURL == "" || m.LoaderSigURL == "" || m.LoaderVersion < 1 {
		return "", errors.New("loader: this release carries no boot loader")
	}
	installed := InstalledLoaderVersion(dirs)
	if m.LoaderVersion <= installed {
		return fmt.Sprintf("loader: version %d already installed", installed), nil
	}
	if failed := markerVersion(filepath.Join(dirs.ESP, loaderFailedFile)); failed == m.LoaderVersion && !retryFailed {
		return "", fmt.Errorf("loader: version %d did not start on this machine before, not retrying", failed)
	}
	kPath := filepath.Join(dirs.ESP, "kernelcache-next.efi")
	if _, err := FetchTo(ctx, m.LoaderURL, kPath); err != nil {
		return "", err
	}
	if err := VerifySHA256(kPath, m.LoaderHash); err != nil {
		os.Remove(kPath)
		return "", err
	}
	if got := fileLoaderVersion(kPath); got != m.LoaderVersion {
		os.Remove(kPath)
		return "", fmt.Errorf("loader: image reports version %d, manifest says %d", got, m.LoaderVersion)
	}
	sPath := kPath + ".sig"
	if _, err := FetchTo(ctx, m.LoaderSigURL, sPath); err != nil {
		os.Remove(kPath)
		return "", err
	}
	if err := VerifySHA256(sPath, m.LoaderSigHash); err != nil {
		os.Remove(kPath)
		os.Remove(sPath)
		return "", err
	}
	img, err := os.ReadFile(kPath)
	if err != nil {
		return "", err
	}
	sig, err := os.ReadFile(sPath)
	if err != nil {
		return "", err
	}
	signingPub, _, err := trust.VerifyCert(vm.cert, vm.certSig, rootPub, time.Now())
	if err != nil {
		return "", fmt.Errorf("loader: %w", err)
	}
	if !trust.Verify(img, sig, signingPub) {
		os.Remove(kPath)
		os.Remove(sPath)
		return "", errors.New("loader: signature invalid, refusing")
	}
	os.Remove(filepath.Join(dirs.ESP, loaderRanFile))
	sum := sha256.Sum256(img)
	if err := writeMarker(filepath.Join(dirs.ESP, loaderCandidateFile),
		"version="+strconv.Itoa(m.LoaderVersion), "sha256="+hex.EncodeToString(sum[:])); err != nil {
		return "", err
	}
	if err := WriteBootState(filepath.Join(dirs.ESP, "boot-state"), BootState{Target: "next", Trial: true, Attempts: 1}); err != nil {
		return "", err
	}
	if err := commitDir(dirs.ESP); err != nil {
		return "", err
	}
	syscall.Sync()
	return fmt.Sprintf("loader: version %d staged, it is tried once on the next boot", m.LoaderVersion), nil
}

func fileLoaderVersion(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return LoaderVersionOf(b)
}

func installLoaderImage(dirs StageDirs, image string) error {
	boot := loaderBootPath(dirs)
	if _, err := os.Stat(boot); err == nil {
		if err := copyFileSync(boot, filepath.Join(dirs.ESP, loaderPrevFile)); err != nil {
			return fmt.Errorf("loader: keep previous: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(boot), 0o755); err != nil {
		return err
	}
	if err := copyFileSync(image, boot); err != nil {
		return fmt.Errorf("loader: install: %w", err)
	}
	syscall.Sync()
	return nil
}

func HandleLoaderCandidate(dirs StageDirs) (string, error) {
	if dirs.ESP == "" {
		return "", nil
	}
	cand := readKeyFile(filepath.Join(dirs.ESP, loaderCandidateFile))
	version, _ := strconv.Atoi(cand["version"])
	if version == 0 {
		return "", nil
	}
	defer cancelLoaderCandidate(dirs)
	ran := markerVersion(filepath.Join(dirs.ESP, loaderRanFile))
	kPath := filepath.Join(dirs.ESP, "kernelcache-next.efi")
	if ran != version {
		if err := writeMarker(filepath.Join(dirs.ESP, loaderFailedFile), "version="+strconv.Itoa(version)); err != nil {
			return "", err
		}
		return fmt.Sprintf("loader: version %d did not start, the previous loader stays", version), nil
	}
	img, err := os.ReadFile(kPath)
	if err != nil {
		return "", fmt.Errorf("loader: candidate image missing: %w", err)
	}
	sum := sha256.Sum256(img)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), cand["sha256"]) {
		return "", errors.New("loader: candidate image changed since it was staged, not installing")
	}
	if err := installLoaderImage(dirs, kPath); err != nil {
		return "", err
	}
	os.Remove(filepath.Join(dirs.ESP, loaderFailedFile))
	return fmt.Sprintf("loader: version %d started this boot and is now installed", version), nil
}

func RepairLoader(dirs StageDirs, image, sig, rootPub []byte) (string, error) {
	if dirs.ESP == "" {
		return "", errors.New("loader: no ESP configured")
	}
	cert, err := os.ReadFile(filepath.Join(dirs.ESP, "signing-cert.json"))
	if err != nil {
		return "", fmt.Errorf("loader: signing cert: %w", err)
	}
	certSig, err := os.ReadFile(filepath.Join(dirs.ESP, "signing-cert.json.sig"))
	if err != nil {
		return "", fmt.Errorf("loader: signing cert signature: %w", err)
	}
	signingPub, _, err := trust.VerifyCert(cert, certSig, rootPub, time.Now())
	if err != nil {
		return "", fmt.Errorf("loader: %w", err)
	}
	if !trust.Verify(image, sig, signingPub) {
		return "", errors.New("loader: signature invalid, refusing")
	}
	tmp, err := os.CreateTemp(dirs.ESP, ".loader-repair-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(image); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := installLoaderImage(dirs, tmp.Name()); err != nil {
		return "", err
	}
	return fmt.Sprintf("loader: version %d installed", LoaderVersionOf(image)), nil
}

func KernelcacheVersion(path string) string {
	f, err := pe.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if s := f.Section(".atomver"); s != nil {
		if b, err := s.Data(); err == nil {
			if v := strings.Trim(string(b), "\x00 \n"); v != "" {
				return "v" + strings.TrimPrefix(v, "v")
			}
		}
	}
	if s := f.Section(".cmdline"); s != nil {
		if b, err := s.Data(); err == nil {
			for _, arg := range strings.Fields(strings.Trim(string(b), "\x00")) {
				if v, ok := strings.CutPrefix(arg, "atom.version="); ok {
					return v
				}
			}
		}
	}
	return ""
}

type BootInfo struct {
	Target string            `json:"target"`
	Trial  bool              `json:"trial"`
	Slots  map[string]string `json:"slots"`
}

func ReadBootInfo(dirs StageDirs) BootInfo {
	bs, _ := ReadBootState(filepath.Join(dirs.ESP, "boot-state"))
	info := BootInfo{Target: bs.Target, Trial: bs.Trial, Slots: map[string]string{}}
	if info.Target == "" {
		info.Target = "active"
	}
	cand := markerVersion(filepath.Join(dirs.ESP, loaderCandidateFile))
	for _, slot := range []string{"active", "next", "prev", "recovery"} {
		p := filepath.Join(dirs.ESP, "kernelcache-"+slot+".efi")
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if slot == "next" && cand != 0 {
			info.Slots[slot] = "loader " + strconv.Itoa(cand)
			continue
		}
		v := KernelcacheVersion(p)
		if v == "" {
			v = "present"
		}
		info.Slots[slot] = v
	}
	return info
}
