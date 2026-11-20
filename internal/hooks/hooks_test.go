package hooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFollowsLinkedHooks(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "ran")
	target := filepath.Join(root, "libexec", "hook")
	os.MkdirAll(filepath.Dir(target), 0o755)
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho \"$1\" >> "+out+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "kernel.d")
	os.MkdirAll(dir, 0o755)
	if err := os.Symlink("../libexec/hook", filepath.Join(dir, "50-linked")); err != nil {
		t.Fatal(err)
	}
	if err := Run("kernel", dir, "staged", nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || strings.TrimSpace(string(got)) != "staged" {
		t.Fatalf("the linked hook did not run: %q %v", got, err)
	}
}

func TestRunSkipsWhatIsNotAnExecutableFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "plain"), []byte("#!/bin/sh\nexit 1\n"), 0o644)
	os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	os.Symlink("missing", filepath.Join(dir, "dangling"))
	if err := Run("kernel", dir, "staged", nil); err != nil {
		t.Fatal(err)
	}
}
