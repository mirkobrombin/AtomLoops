package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Mock OTA daemon.
// Demonstrates WAL update, staging via hardlink, and pre-verification.

type Manifest struct {
	Version   string `json:"version"`
	RootHash  string `json:"root_hash"`
	RootFSURL string `json:"rootfs_url"`
	KCacheURL string `json:"kernelcache_url"`
}

type Deployment struct {
	RootFS struct {
		Current       string `json:"current"`
		Pending       string `json:"pending"`
		Rollback      string `json:"rollback"`
		BootAttempts  int    `json:"boot_attempts"`
		MaxAttempts   int    `json:"max_attempts"`
		LastKnownGood string `json:"last_known_good"`
	} `json:"rootfs"`
	KernelCache struct {
		State           string `json:"state"`
		StableBoots     int    `json:"stable_boots"`
		StableThreshold int    `json:"stable_threshold"`
		Format          string `json:"format"`
	} `json:"kernelcache"`
	Security struct {
		Level      int  `json:"level"`
		DmVerity   bool `json:"dm_verity"`
		SecureBoot bool `json:"secure_boot"`
	} `json:"security"`
}

const (
	deployFile    = "deployment.json"
	deployFileBak = "deployment.json.bak"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ota-daemon-mock <staging-dir>")
		os.Exit(1)
	}
	stagingDir := os.Args[1]

	fmt.Println("[daemon] mock OTA daemon starting")

	m := loadMockManifest()

	activePath := filepath.Join(stagingDir, "rootfs-active.erofs")

	local := hashFile(activePath)
	if local == "" {
		fmt.Println("[daemon] no local rootfs found, treating as first install")
	} else if local == m.RootHash {
		fmt.Println("[daemon] local rootfs is up to date")
		os.Exit(0)
	}

	fmt.Printf("[daemon] update available: %s\n", m.Version)

	nextPath := filepath.Join(stagingDir, "rootfs-next.erofs")
	fmt.Printf("[daemon] mocking download to %s\n", nextPath)
	if err := copyFile(m.RootFSURL, nextPath); err != nil {
		fmt.Fprintf(os.Stderr, "[daemon] download failed: %v\n", err)
		os.Exit(1)
	}

	if hashFile(nextPath) != m.RootHash {
		fmt.Fprintf(os.Stderr, "[daemon] pre-verification failed\n")
		os.Exit(1)
	}
	fmt.Println("[daemon] pre-verification passed")

	deployPath := filepath.Join(stagingDir, deployFile)
	if err := writePendingWAL(deployPath, m.Version); err != nil {
		fmt.Fprintf(os.Stderr, "[daemon] WAL update failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[daemon] update staged, reboot to apply")
}

func loadMockManifest() Manifest {
	return Manifest{
		Version:   "v2",
		RootHash:  "aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd",
		RootFSURL: "/dev/zero",
	}
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.CopyN(out, in, 1024*1024); err != nil {
		return err
	}
	return out.Sync()
}

func writePendingWAL(deployPath, version string) error {
	d := Deployment{}
	f, _ := os.ReadFile(deployPath)
	json.Unmarshal(f, &d)

	d.RootFS.Pending = version
	if d.RootFS.LastKnownGood == "" {
		d.RootFS.LastKnownGood = d.RootFS.Current
	}
	data, _ := json.MarshalIndent(d, "", "  ")

	tmp := deployPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, deployPath); err != nil {
		return err
	}
	return nil
}
