package otad

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type KernelFamily struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	Hash          string `json:"hash"`
	SigURL        string `json:"sig_url"`
	SigHash       string `json:"sig_hash"`
	KernelRelease string `json:"kernel_release,omitempty"`
}

var boardFamilies = map[string]string{
	"nvidia,tegra234": "l4t",
}

var deviceTreeCompatible = "/proc/device-tree/compatible"

func MachineFamily() string {
	b, err := os.ReadFile(deviceTreeCompatible)
	if err != nil {
		return ""
	}
	for _, c := range strings.Split(string(b), "\x00") {
		if f, ok := boardFamilies[c]; ok {
			return f
		}
	}
	return ""
}

func (m Manifest) Family(name string) (KernelFamily, bool) {
	for _, f := range m.KernelFamilies {
		if f.Name == name {
			return f, true
		}
	}
	return KernelFamily{}, false
}

func familySuffixes(name string) []string {
	return []string{"." + name + ".efi", "." + name + ".efi.sig"}
}

func knownFamilies() []string {
	var out []string
	for _, f := range boardFamilies {
		out = append(out, f)
	}
	return out
}

func stageFamily(ctx context.Context, m Manifest, esp string) error {
	for _, name := range knownFamilies() {
		for _, s := range familySuffixes(name) {
			os.Remove(filepath.Join(esp, "kernelcache-next"+s))
		}
	}
	name := MachineFamily()
	if name == "" {
		return nil
	}
	f, ok := m.Family(name)
	if !ok {
		return nil
	}
	if f.SigURL == "" {
		return fmt.Errorf("stage: the %s kernelcache carries no signature -- refusing", name)
	}
	files := []struct{ url, hash, suffix string }{
		{f.URL, f.Hash, "." + name + ".efi"},
		{f.SigURL, f.SigHash, "." + name + ".efi.sig"},
	}
	for _, x := range files {
		p := filepath.Join(esp, "kernelcache-next"+x.suffix)
		if _, err := FetchTo(ctx, x.url, p); err != nil {
			return err
		}
		if err := VerifySHA256(p, x.hash); err != nil {
			os.Remove(p)
			return err
		}
	}
	return nil
}

const familiesPending = "kernelcache-families-pending"

func markFamilies(esp string) error {
	p := filepath.Join(esp, familiesPending)
	if err := os.WriteFile(p, []byte("pending\n"), 0o644); err != nil {
		return err
	}
	return syncDir(esp)
}

func promoteFamilies(esp string) error {
	marker := filepath.Join(esp, familiesPending)
	b, _ := os.ReadFile(marker)
	done := map[string]bool{}
	for _, l := range strings.Fields(string(b)) {
		done[l] = true
	}
	for _, name := range knownFamilies() {
		if done[name] {
			continue
		}
		suffixes := familySuffixes(name)
		staged := 0
		for _, s := range suffixes {
			if nonEmpty(filepath.Join(esp, "kernelcache-next"+s)) {
				staged++
			}
		}
		if staged != 0 && staged != len(suffixes) {
			return fmt.Errorf("promote: kernelcache for %s partially staged", name)
		}
		for _, s := range suffixes {
			next := filepath.Join(esp, "kernelcache-next"+s)
			active := filepath.Join(esp, "kernelcache-active"+s)
			prev := filepath.Join(esp, "kernelcache-prev"+s)
			if staged != 0 && sameFileContent(active, next) {
				continue
			}
			if nonEmpty(active) {
				if err := promoteStep(true, active, prev); err != nil {
					return err
				}
			} else if err := removeSync(prev); err != nil {
				return err
			}
			if staged != 0 {
				if err := promoteStep(true, next, active); err != nil {
					return err
				}
			} else if err := removeSync(active); err != nil {
				return err
			}
		}
		done[name] = true
		var list []string
		for n := range done {
			list = append(list, n)
		}
		if err := os.WriteFile(marker, []byte(strings.Join(list, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}
	if err := removeSync(marker); err != nil {
		return err
	}
	return syncDir(esp)
}

func removeSync(p string) error {
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
