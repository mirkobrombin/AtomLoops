package otad

import (
	"os"
	"path/filepath"
	"testing"
)

func mockPCI(t *testing.T, class, vendor string) string {
	t.Helper()
	root := t.TempDir()
	dev := filepath.Join(root, "bus", "pci", "devices", "0000:01:00.0")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dev, "class"), []byte(class+"\n"), 0o644)
	os.WriteFile(filepath.Join(dev, "vendor"), []byte(vendor+"\n"), 0o644)
	return root
}

func TestDetectGPUChips(t *testing.T) {
	cases := []struct {
		class, vendor, want string
	}{
		{"0x030000", "0x10de", "nvidia"}, // NVIDIA display
		{"0x030000", "0x1002", "amd"},    // AMD display
		{"0x030000", "0x8086", ""},       // Intel display -> base
		{"0x040300", "0x10de", ""},       // NVIDIA audio function (not display) -> ignored
	}
	for _, c := range cases {
		got := DetectGPUChips(mockPCI(t, c.class, c.vendor))
		g := ""
		if len(got) > 0 {
			g = got[0]
		}
		if g != c.want {
			t.Errorf("class=%s vendor=%s -> %v, want %q", c.class, c.vendor, got, c.want)
		}
	}
}

func TestMatchesHardware(t *testing.T) {
	nv := FirmwareBundleSpec{Chips: []string{"nvidia"}, KernelMin: "7.1.3", KernelMax: "7.1.3"}
	amd := FirmwareBundleSpec{Chips: []string{"amd"}}
	generic := FirmwareBundleSpec{} // no chips, no kernel bound
	cases := []struct {
		name   string
		spec   FirmwareBundleSpec
		chips  []string
		kernel string
		want   bool
	}{
		{"nvidia bundle, nvidia box, exact kernel", nv, []string{"nvidia"}, "7.1.3", true},
		{"nvidia bundle, nvidia box, WRONG kernel", nv, []string{"nvidia"}, "6.19.14", false},
		{"nvidia bundle, amd box", nv, []string{"amd"}, "7.1.3", false},
		{"nvidia bundle, no gpu", nv, nil, "7.1.3", false},
		{"amd bundle, amd box", amd, []string{"amd"}, "7.1.3", true},
		{"generic bundle, anything", generic, nil, "7.1.3", true},
	}
	for _, c := range cases {
		if got := c.spec.MatchesHardware(c.chips, c.kernel); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCoupledKernelCheck(t *testing.T) {
	target := "9.9.9-target" // guaranteed != the running kernel
	nvTarget := FirmwareBundleSpec{Name: "nvidia", Chips: []string{"nvidia"}, KernelMin: target, KernelMax: target}
	nvOld := FirmwareBundleSpec{Name: "nvidia", Chips: []string{"nvidia"}, KernelMin: "1.0.0", KernelMax: "1.0.0"}
	amdFw := FirmwareBundleSpec{Name: "amdgpu", Chips: []string{"amd"}} // firmware-only, not kernel-bound
	cases := []struct {
		name    string
		m       Manifest
		chips   []string
		wantErr bool
	}{
		{"no kernel-release: never gated", Manifest{FirmwareBundles: []FirmwareBundleSpec{nvOld}}, []string{"nvidia"}, false},
		{"kernel change, nvidia box, matching bundle: ok", Manifest{KernelRelease: target, FirmwareBundles: []FirmwareBundleSpec{nvTarget}}, []string{"nvidia"}, false},
		{"kernel change, nvidia box, only OLD-kernel bundle: refuse", Manifest{KernelRelease: target, FirmwareBundles: []FirmwareBundleSpec{nvOld}}, []string{"nvidia"}, true},
		{"kernel change, AMD box, nvidia-only offered: ok", Manifest{KernelRelease: target, FirmwareBundles: []FirmwareBundleSpec{nvOld}}, []string{"amd"}, false},
		{"kernel change, nvidia box, firmware-only bundle: ok", Manifest{KernelRelease: target, FirmwareBundles: []FirmwareBundleSpec{amdFw}}, []string{"nvidia"}, false},
		{"kernel unchanged (target==running): never gated", Manifest{KernelRelease: RunningKernel(), FirmwareBundles: []FirmwareBundleSpec{nvOld}}, []string{"nvidia"}, false},
	}
	for _, c := range cases {
		if err := c.m.CoupledKernelCheck(c.chips); (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

func TestCmpKernel(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"7.1.3", "7.1.3", 0},
		{"7.1.3", "7.1.2", 1},
		{"6.19.14", "7.1.3", -1},
		{"7.1.10", "7.1.3", 1}, // numeric, not lexical (10 > 3)
	}
	for _, c := range cases {
		if got := cmpKernel(c.a, c.b); got != c.want {
			t.Errorf("cmpKernel(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
