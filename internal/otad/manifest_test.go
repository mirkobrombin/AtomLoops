package otad

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestParseManifest(t *testing.T) {
	good := `{"version":"v2","min_version":"v1","rootfs_url":"http://x/r","rootfs_hash":"aa","kernelcache_url":"http://x/k","kernelcache_hash":"bb"}`
	m, err := ParseManifest([]byte(good))
	if err != nil {
		t.Fatalf("good manifest rejected: %v", err)
	}
	if m.Version != "v2" || m.RootFSURL == "" {
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
