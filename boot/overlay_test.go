package boot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseOverlay(t *testing.T) {
	cases := []struct {
		in      string
		target  string
		version uint64
		ok      bool
	}{
		{"target=/usr/lib/sinty-framework\nversion=42\n", "/usr/lib/sinty-framework", 42, true},
		{"version=7\ntarget=/usr/share/x", "/usr/share/x", 7, true},
		{"target=/usr/lib/sinty-framework\n", "", 0, false},
		{"target=/usr/lib/x\nversion=0", "", 0, false},
		{"target=/usr/lib/x\nversion=-1", "", 0, false},
		{"target=/etc\nversion=3", "", 0, false},
		{"target=/usr/lib/../../etc\nversion=3", "", 0, false},
		{"target=/usr/lib/x/\nversion=3", "", 0, false},
		{"target=/usr/lib/firmware\nversion=3", "", 0, false},
		{"target=usr/lib/x\nversion=3", "", 0, false},
	}
	for _, c := range cases {
		target, version, ok := parseOverlay(c.in)
		if target != c.target || version != c.version || ok != c.ok {
			t.Errorf("parseOverlay(%q) = %q %d %v, want %q %d %v", c.in, target, version, ok, c.target, c.version, c.ok)
		}
	}
}

func TestOverlayWanted(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "usr/lib/sinty-framework")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !overlayWanted(root, "/usr/lib/sinty-framework", 1) {
		t.Error("a target without a version file must accept a bundle")
	}
	os.WriteFile(filepath.Join(dir, ".overlay-version"), []byte("10\n"), 0o644)
	if overlayWanted(root, "/usr/lib/sinty-framework", 10) {
		t.Error("a bundle as old as the root must be skipped")
	}
	if overlayWanted(root, "/usr/lib/sinty-framework", 9) {
		t.Error("a bundle older than the root must be skipped")
	}
	if !overlayWanted(root, "/usr/lib/sinty-framework", 11) {
		t.Error("a newer bundle must be accepted")
	}
	if overlayWanted(root, "/usr/lib/missing", 99) {
		t.Error("a missing target must be skipped")
	}
	os.Symlink(dir, filepath.Join(root, "usr/lib/link"))
	if overlayWanted(root, "/usr/lib/link", 99) {
		t.Error("a symlinked target must be skipped")
	}
	os.WriteFile(filepath.Join(dir, ".overlay-version"), []byte("garbage"), 0o644)
	if overlayWanted(root, "/usr/lib/sinty-framework", 99) {
		t.Error("an unreadable root version must fail closed")
	}
}

func TestBundleDirs(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "amd"), 0o755)
	os.MkdirAll(filepath.Join(root, "singularity-framework"), 0o755)
	os.WriteFile(filepath.Join(root, "stray-file"), []byte("x"), 0o644)
	os.Symlink(filepath.Join(root, "amd"), filepath.Join(root, "link"))
	got := bundleDirs(root)
	want := []string{filepath.Join(root, "amd"), filepath.Join(root, "singularity-framework")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("bundleDirs = %v, want %v", got, want)
	}
	if bundleDirs(filepath.Join(root, "missing")) != nil {
		t.Fatal("a missing firmware dir must give no bundles")
	}
}
