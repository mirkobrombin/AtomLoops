package otad

import (
	"runtime"
	"strings"
	"testing"
)

func TestManifestForAnotherArchIsRefused(t *testing.T) {
	other := "aarch64"
	if Arch(runtime.GOARCH) == "aarch64" {
		other = "x86_64"
	}
	base := `{"version":"v1","min_version":"v0","rootfs_url":"r","rootfs_hash":"h","kernelcache_url":"k","kernelcache_hash":"h","product_name":"Sinty OS","product_version":"26","product_build":"26A1"`
	if _, err := ParseManifest([]byte(base + `,"arch":"` + other + `"}`)); err == nil || !strings.Contains(err.Error(), "built for") {
		t.Fatalf("foreign manifest accepted: %v", err)
	}
	if _, err := ParseManifest([]byte(base + `,"arch":"` + Arch(runtime.GOARCH) + `"}`)); err != nil {
		t.Fatalf("own manifest refused: %v", err)
	}
	if _, err := ParseManifest([]byte(base + `}`)); err != nil {
		t.Fatalf("manifest without arch refused: %v", err)
	}
}
