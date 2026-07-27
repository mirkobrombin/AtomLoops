package signing

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/otad"
)

// TestReleaseToPromoteEndToEnd drives the WHOLE pipeline the way it runs in
// production, proving the release tools (this package) and the device daemon
// (otad) compose: generate the root key, build + sign a manifest over real
// artifacts, serve them over HTTP, then on the device side fetch + verify + stage
// the update and greenboot-promote it, checking the WAL and the anti-rollback
// counter end to end.
func TestReleaseToPromoteEndToEnd(t *testing.T) {
	dir := t.TempDir()
	blob := func(name string, n int) string {
		b := make([]byte, n)
		rand.Read(b)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// The release/distribution server serves everything under dir (files written
	// after it starts are served fine).
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	// --- Release side ---
	rootfs := blob("rootfs.bin", 4096)
	kc := blob("kc.bin", 2048)
	priv := filepath.Join(dir, "root.key")
	pub := filepath.Join(dir, "root.pub")
	if err := GenerateKeyFiles(priv, pub); err != nil {
		t.Fatal(err)
	}
	// Root issues an operational signing cert; manifests are signed by it.
	cert := filepath.Join(dir, "signing-cert.json")
	signingKey := filepath.Join(dir, "signing.key")
	if err := IssueCert(priv, cert, signingKey, 1, 365*24*time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "manifest.json")
	if _, err := BuildManifest(manifest, "v2", "v1", rootfs, srv.URL+"/rootfs.bin", kc, srv.URL+"/kc.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := SignManifest(signingKey, manifest); err != nil { // signed by the SIGNING key
		t.Fatal(err)
	}

	// --- Device side ---
	rootPub, _ := os.ReadFile(pub)
	wal := filepath.Join(dir, "deployment.json")
	if err := deployment.New("dev-int", "v1").Save(wal); err != nil {
		t.Fatal(err)
	}
	dirs := otad.StageDirs{Rootfs: filepath.Join(dir, "slot-rootfs"), ESP: filepath.Join(dir, "slot-esp")}

	if _, err := otad.Stage(context.Background(), wal, srv.URL+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	// Artifacts landed and the candidate is pending.
	for _, f := range []string{filepath.Join(dirs.Rootfs, "rootfs-next.erofs"), filepath.Join(dirs.ESP, "kernelcache-next.efi")} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("artifact not staged: %s", f)
		}
	}
	d, _ := deployment.Load(wal)
	if d.RootFS.Pending != "v2" {
		t.Fatalf("after stage, pending = %q, want v2", d.RootFS.Pending)
	}

	// Promotion requires proof the running system is the candidate: point the
	// booted-identity check at a cmdline carrying the candidate's verity hash.
	d, _ = deployment.Load(wal)
	if d.RootFS.PendingHash == "" {
		d.RootFS.PendingHash = "int-hash-v2"
		if err := d.Save(wal); err != nil {
			t.Fatal(err)
		}
	}
	cmdline := filepath.Join(dir, "cmdline")
	os.WriteFile(cmdline, []byte("ATOM_ROOT_HASH="+d.RootFS.PendingHash+"\n"), 0o644)
	defer otad.SetBootedCmdlinePath(cmdline)()

	// Greenboot the candidate to stability with the hardware counter armed.
	hw := filepath.Join(dir, "counter")
	os.WriteFile(hw, []byte("0"), 0o644)
	counter := otad.CommandCounter{ReadCmd: "cat " + hw, AdvanceCmd: "echo $ATOM_COUNTER > " + hw}
	health := filepath.Join(dir, "no-health-dir") // absent = healthy
	var lastMsg string
	for i := 0; i < 3; i++ {
		msg, err := otad.BootSuccess(wal, health, counter, dirs)
		if err != nil {
			t.Fatal(err)
		}
		lastMsg = msg
	}

	// Candidate promoted to current, and the anti-rollback counter is armed.
	d, _ = deployment.Load(wal)
	if d.RootFS.Current != "v2" || d.HasPending() {
		t.Fatalf("candidate not promoted: current=%q pending=%v (%s)", d.RootFS.Current, d.HasPending(), lastMsg)
	}
	if v, _ := counter.Read(); v != 2 {
		t.Errorf("anti-rollback counter = %d, want 2 (kernelcache version)", v)
	}
}

// TestFirmwareReleaseToPromoteEndToEnd drives the firmware add-on track through the
// same real pipeline: the release tools sign a manifest carrying a firmware image +
// hash tree, the device stages it (fetch + verify + persist the boot anchor + activate
// the slot), the initramfs-side anchor verification recovers the trusted verity hash,
// and a clean device-probe promotes the firmware while dropping the rollback backups.
func TestFirmwareReleaseToPromoteEndToEnd(t *testing.T) {
	dir := t.TempDir()
	blob := func(name string, n int) string {
		b := make([]byte, n)
		rand.Read(b)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	// --- Release side: rootfs + kernelcache + a firmware add-on track ---
	rootfs := blob("rootfs.bin", 4096)
	kc := blob("kc.bin", 2048)
	fwImg := blob("firmware.img", 8192)
	fwHashTree := blob("firmware.hash", 1024)
	const fwVerityHash = "8e557345916c5824e9999845054535e4f27d761c83cdc8ce9c847fc706dc4601"

	priv := filepath.Join(dir, "root.key")
	pub := filepath.Join(dir, "root.pub")
	if err := GenerateKeyFiles(priv, pub); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, "signing-cert.json")
	signingKey := filepath.Join(dir, "signing.key")
	if err := IssueCert(priv, cert, signingKey, 1, 365*24*time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "manifest.json")
	fw := FirmwareSpec{
		Version: 5, MinVersion: 0,
		ImageFile: fwImg, ImageURL: srv.URL + "/firmware.img",
		VerityHash:   fwVerityHash,
		HashTreeFile: fwHashTree, HashTreeURL: srv.URL + "/firmware.hash",
	}
	if _, err := BuildManifest(manifest, "v2", "v1", rootfs, srv.URL+"/rootfs.bin", kc, srv.URL+"/kc.bin", fw); err != nil {
		t.Fatal(err)
	}
	if _, err := SignManifest(signingKey, manifest); err != nil {
		t.Fatal(err)
	}

	// --- Device side: stage the firmware track ---
	rootPub, _ := os.ReadFile(pub)
	wal := filepath.Join(dir, "deployment.json")
	if err := deployment.New("dev-fw", "v1").Save(wal); err != nil {
		t.Fatal(err)
	}
	fwDir := filepath.Join(dir, "slot-firmware")
	dirs := otad.StageDirs{Rootfs: filepath.Join(dir, "slot-rootfs"), ESP: filepath.Join(dir, "slot-esp"), Firmware: fwDir}
	if _, err := otad.Stage(context.Background(), wal, srv.URL+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("Stage with firmware: %v", err)
	}

	// The legacy single-firmware manifest folds into a bundle named "default"; its image
	// and hash tree are activated in the bundle subdir and the boot anchor verifies to the
	// trusted verity hash, keyed to the same root pubkey the loader carries.
	bdir := filepath.Join(fwDir, "default")
	if _, err := os.Stat(filepath.Join(bdir, "firmware-active.img")); err != nil {
		t.Errorf("firmware image not activated: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bdir, "firmware-active.hash")); err != nil {
		t.Errorf("firmware hash tree not activated: %v", err)
	}
	gotHash, gotVer, err := otad.VerifyFirmwareAnchor(bdir, "active", rootPub, time.Now(), "default")
	if err != nil {
		t.Fatalf("firmware boot anchor does not verify: %v", err)
	}
	if gotHash != fwVerityHash || gotVer != 5 {
		t.Fatalf("anchor hash/ver = %q/%d, want %q/5", gotHash, gotVer, fwVerityHash)
	}

	// A clean device-probe at threshold 1 promotes the firmware bundle and drops backups.
	fd, _ := deployment.Load(wal)
	fd.Firmware.Bundle("default").StableThreshold = 1
	if err := fd.Save(wal); err != nil {
		t.Fatal(err)
	}
	if _, err := otad.FirmwareBootConfirm(wal, dirs, "default", true); err != nil {
		t.Fatalf("firmware confirm: %v", err)
	}
	fd, _ = deployment.Load(wal)
	if fd.HasPendingFirmware("default") || fd.Firmware.Bundle("default").CurrentVersion != 5 {
		t.Fatalf("firmware not promoted: %+v", fd.Firmware.Bundle("default"))
	}
}

// TestMultiBundleFirmwareEndToEnd proves two independently-versioned firmware bundles
// stage into separate slot dirs, each verifies to its OWN trusted verity hash by name,
// and each promotes independently through the real release+device pipeline.
func TestMultiBundleFirmwareEndToEnd(t *testing.T) {
	dir := t.TempDir()
	blob := func(name string, n int) string {
		b := make([]byte, n)
		rand.Read(b)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	rootfs := blob("rootfs.bin", 4096)
	kc := blob("kc.bin", 2048)
	wifiImg, wifiHT := blob("wifi.img", 8192), blob("wifi.hash", 1024)
	gpuImg, gpuHT := blob("gpu.img", 8192), blob("gpu.hash", 1024)

	priv := filepath.Join(dir, "root.key")
	pub := filepath.Join(dir, "root.pub")
	if err := GenerateKeyFiles(priv, pub); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, "signing-cert.json")
	signingKey := filepath.Join(dir, "signing.key")
	if err := IssueCert(priv, cert, signingKey, 1, 365*24*time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "manifest.json")
	if _, err := BuildManifest(manifest, "v2", "v1", rootfs, srv.URL+"/rootfs.bin", kc, srv.URL+"/kc.bin",
		FirmwareSpec{Name: "intel-wifi-modern", Version: 3, ImageFile: wifiImg, ImageURL: srv.URL + "/wifi.img",
			VerityHash: "a1b2c3", HashTreeFile: wifiHT, HashTreeURL: srv.URL + "/wifi.hash", Chips: []string{"iwlwifi"}},
		FirmwareSpec{Name: "amdgpu", Version: 2, ImageFile: gpuImg, ImageURL: srv.URL + "/gpu.img",
			VerityHash: "d4e5f6", HashTreeFile: gpuHT, HashTreeURL: srv.URL + "/gpu.hash", Chips: []string{"amdgpu"}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := SignManifest(signingKey, manifest); err != nil {
		t.Fatal(err)
	}

	rootPub, _ := os.ReadFile(pub)
	wal := filepath.Join(dir, "deployment.json")
	if err := deployment.New("dev-mb", "v1").Save(wal); err != nil {
		t.Fatal(err)
	}
	fwDir := filepath.Join(dir, "slot-firmware")
	dirs := otad.StageDirs{Rootfs: filepath.Join(dir, "slot-rootfs"), ESP: filepath.Join(dir, "slot-esp"), Firmware: fwDir}
	if _, err := otad.Stage(context.Background(), wal, srv.URL+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("Stage multi-bundle: %v", err)
	}

	// Each bundle lands in its own slot dir and its anchor verifies to its own hash by name.
	for _, tc := range []struct{ name, hash string }{{"intel-wifi-modern", "a1b2c3"}, {"amdgpu", "d4e5f6"}} {
		bdir := filepath.Join(fwDir, tc.name)
		if _, err := os.Stat(filepath.Join(bdir, "firmware-active.img")); err != nil {
			t.Errorf("bundle %q image not activated: %v", tc.name, err)
		}
		got, _, err := otad.VerifyFirmwareAnchor(bdir, "active", rootPub, time.Now(), tc.name)
		if err != nil {
			t.Fatalf("bundle %q anchor verify: %v", tc.name, err)
		}
		if got != tc.hash {
			t.Errorf("bundle %q verity hash = %q, want %q", tc.name, got, tc.hash)
		}
		// A bundle's anchor must NOT vouch for a different bundle's name.
		if _, _, err := otad.VerifyFirmwareAnchor(bdir, "active", rootPub, time.Now(), "no-such-bundle"); err == nil {
			t.Errorf("bundle %q anchor must not vouch for an unknown bundle", tc.name)
		}
	}

	// Promote wifi (threshold 1); fail gpu's probe -> it rolls back. Independent tracks.
	fd, _ := deployment.Load(wal)
	fd.Firmware.Bundle("intel-wifi-modern").StableThreshold = 1
	if err := fd.Save(wal); err != nil {
		t.Fatal(err)
	}
	if _, err := otad.FirmwareBootConfirm(wal, dirs, "intel-wifi-modern", true); err != nil {
		t.Fatalf("wifi confirm: %v", err)
	}
	if _, err := otad.FirmwareBootConfirm(wal, dirs, "amdgpu", false); err != nil {
		t.Fatalf("gpu confirm: %v", err)
	}
	fd, _ = deployment.Load(wal)
	if fd.HasPendingFirmware("intel-wifi-modern") || fd.Firmware.Bundle("intel-wifi-modern").CurrentVersion != 3 {
		t.Errorf("wifi should be promoted: %+v", fd.Firmware.Bundle("intel-wifi-modern"))
	}
	if fd.HasPendingFirmware("amdgpu") || fd.Firmware.Bundle("amdgpu").MinVersion != 0 {
		t.Errorf("gpu should have rolled back without advancing its floor: %+v", fd.Firmware.Bundle("amdgpu"))
	}
}
