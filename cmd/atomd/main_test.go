package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsInstalledMarker(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "installed")
	if isInstalled(marker) {
		t.Fatal("should be false when the marker is absent (fail-safe: live)")
	}
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if !isInstalled(marker) {
		t.Fatal("should be true when the marker exists (installed)")
	}
}
