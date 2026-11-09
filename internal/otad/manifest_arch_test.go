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
	if _, err := ParseManifestFor([]byte(base+`}`), "x86_64"); err != nil {
		t.Fatalf("manifest without arch refused on x86_64: %v", err)
	}
	if _, err := ParseManifestFor([]byte(base+`}`), "aarch64"); err == nil {
		t.Fatal("manifest without arch accepted as aarch64")
	}
	if _, err := ParseManifestFor([]byte(base+`,"arch":"aarch64"}`), "aarch64"); err != nil {
		t.Fatalf("aarch64 manifest refused when asked for aarch64: %v", err)
	}
}

func TestLoaderFileNamePerArch(t *testing.T) {
	if LoaderFileName("aarch64") != "BOOTAA64.EFI" || LoaderFileName("x86_64") != "BOOTX64.EFI" {
		t.Fatal("wrong removable boot path")
	}
	if !strings.HasSuffix(loaderBootPath(StageDirs{ESP: "/e/EFI/atom"}), LoaderFileName(Arch(runtime.GOARCH))) {
		t.Fatal("loader path ignores the running arch")
	}
}
