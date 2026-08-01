package otad

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseManifest(t *testing.T) {
	good := `{"version":"v2","min_version":"v1","product_name":"Sinty OS Event Horizon","product_version":"26","product_build":"26A010","rootfs_url":"http://x/r","rootfs_hash":"aa","kernelcache_url":"http://x/k","kernelcache_hash":"bb"}`
	m, err := ParseManifest([]byte(good))
	if err != nil {
		t.Fatalf("good manifest rejected: %v", err)
	}
	if m.Version != "v2" || m.RootFSURL == "" || m.ProductName != "Sinty OS Event Horizon" || m.ProductVersion != "26" || m.ProductBuild != "26A010" {
		t.Fatalf("parsed wrong: %+v", m)
	}
	bad := []string{
		`{"rootfs_url":"x","rootfs_hash":"aa","kernelcache_url":"y","kernelcache_hash":"bb"}`, // no version
		`{"version":"v2","kernelcache_url":"y","kernelcache_hash":"bb"}`,                      // no rootfs
		`{"version":"v2","rootfs_url":"x","rootfs_hash":"aa"}`,                                // no kernelcache
		`not json`,
	}
	for i, b := range bad {
		if _, err := ParseManifest([]byte(b)); err == nil {
			t.Errorf("bad manifest %d accepted", i)
		}
	}
}

func TestParseManifestRejectsInvalidProductMetadata(t *testing.T) {
	prefix := `{"version":"v2","rootfs_url":"x","rootfs_hash":"aa","kernelcache_url":"y","kernelcache_hash":"bb",`
	bad := []string{
		prefix + `"product_name":" Sinty OS Event Horizon"}`,
		prefix + `"product_version":"26\npreview"}`,
		prefix + `"product_build":"` + strings.Repeat("x", 129) + `"}`,
		prefix + `"product_build":26010}`,
		prefix + `"product_version":null}`,
		prefix + `"PRODUCT_NAME":null}`,
		prefix + `"product_name":"Sinty OS Event \u202eHorizon"}`,
		prefix + `"product_build":"26A0\u200b10"}`,
		prefix + `"product_name":"Sinty OS\u2028Event Horizon"}`,
		prefix + `"product_name":"Sinty OS\u2029Event Horizon"}`,
	}
	for i, body := range bad {
		if _, err := ParseManifest([]byte(body)); err == nil {
			t.Errorf("invalid product metadata %d accepted", i)
		}
	}
	invalidUTF8 := append([]byte(prefix+`"product_name":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"}`)...)
	if _, err := ParseManifest(invalidUTF8); err == nil {
		t.Error("invalid UTF-8 product metadata accepted")
	}
}

func TestVerifySHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	data := []byte("atom loops rootfs image contents")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	good := hex.EncodeToString(sum[:])

	if err := VerifySHA256(path, good); err != nil {
		t.Errorf("correct hash rejected: %v", err)
	}
	// A single flipped bit must fail.
	bad := "00" + good[2:]
	if err := VerifySHA256(path, bad); err == nil {
		t.Error("wrong hash accepted")
	}
	// A malformed expected hash is an error, not a panic.
	if err := VerifySHA256(path, "xyz"); err == nil {
		t.Error("malformed expected hash accepted")
	}
	// A missing file is an error.
	if err := VerifySHA256(filepath.Join(dir, "nope"), good); err == nil {
		t.Error("missing file accepted")
	}
}
