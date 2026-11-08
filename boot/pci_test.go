package boot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPCIWanted(t *testing.T) {
	dir := t.TempDir()
	old := PCIDevices
	PCIDevices = filepath.Join(dir, "devices")
	defer func() { PCIDevices = old }()
	for name, vendor := range map[string]string{"0000:00:02.0": "0x8086\n", "0000:01:00.0": "0x10de\n"} {
		os.MkdirAll(filepath.Join(PCIDevices, name), 0o755)
		os.WriteFile(filepath.Join(PCIDevices, name, "vendor"), []byte(vendor), 0o644)
	}
	file := func(s string) string {
		p := filepath.Join(dir, "pci-"+s)
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	cases := []struct {
		path string
		want bool
	}{
		{filepath.Join(dir, "missing"), true},
		{file("0x10de"), true},
		{file("10DE"), true},
		{file("0x1002"), false},
		{file("0x1002 0x8086"), true},
		{file(""), false},
	}
	for _, c := range cases {
		if got := pciWanted(c.path); got != c.want {
			data, _ := os.ReadFile(c.path)
			t.Errorf("%q: %v, want %v", data, got, c.want)
		}
	}
}
