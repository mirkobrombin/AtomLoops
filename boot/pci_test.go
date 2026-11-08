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

func TestFirmwareChoice(t *testing.T) {
	dir := t.TempDir()
	old := PCIDevices
	PCIDevices = filepath.Join(dir, "devices")
	defer func() { PCIDevices = old }()
	add := func(name, vendor, device string) {
		os.MkdirAll(filepath.Join(PCIDevices, name), 0o755)
		os.WriteFile(filepath.Join(PCIDevices, name, "vendor"), []byte(vendor+"\n"), 0o644)
		os.WriteFile(filepath.Join(PCIDevices, name, "device"), []byte(device+"\n"), 0o644)
	}
	add("0000:00:02.0", "0x8086", "0x46a6")
	store := filepath.Join(dir, "choice")
	c := loadChoice(store)
	if len(c.skip) != 0 || c.path == "" {
		t.Fatalf("fresh choice: %+v", c)
	}
	c.keep["nvidia"] = "aaa"
	c.keep["amd"] = "bbb"
	c.save()
	c = loadChoice(store)
	if c.skip["nvidia"] != "aaa" || c.skip["amd"] != "bbb" || len(c.skip) != 2 {
		t.Fatalf("reloaded: %v", c.skip)
	}
	add("0000:01:00.0", "0x10de", "0x2520")
	if c := loadChoice(store); len(c.skip) != 0 {
		t.Fatalf("new hardware must start over: %v", c.skip)
	}
}
