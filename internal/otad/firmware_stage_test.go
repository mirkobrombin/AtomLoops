package otad

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

// TestStageFirmwareTrack verifies the optional firmware track is fetched,
// verified and staged on its own independent slot, and marked pending in the WAL
// via the firmware anti-rollback path, without disturbing the rootfs track.
func TestStageFirmwareTrack(t *testing.T) {
	rootfs := []byte("EROFS rootfs image v2 contents")
	kernel := []byte("UKI kernelcache v2 contents")
	firmware := []byte("signed firmware add-on image v5 contents")

	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	cert := trust.SigningCert{
		Version:       1,
		SigningPubkey: base64.StdEncoding.EncodeToString(signPub),
		IssuedAt:      "2026-01-01T00:00:00Z",
		NotAfter:      "2099-01-01T00:00:00Z",
	}
	certBytes, _ := json.Marshal(cert)
	certSig := ed25519.Sign(rootPriv, certBytes)

	firmwareHashTree := []byte("dm-verity hash tree for firmware v5")

	mux := http.NewServeMux()
	mux.HandleFunc("/rootfs", func(w http.ResponseWriter, r *http.Request) { w.Write(rootfs) })
	mux.HandleFunc("/kernelcache", func(w http.ResponseWriter, r *http.Request) { w.Write(kernel) })
	mux.HandleFunc("/firmware", func(w http.ResponseWriter, r *http.Request) { w.Write(firmware) })
	mux.HandleFunc("/firmware-hashtree", func(w http.ResponseWriter, r *http.Request) { w.Write(firmwareHashTree) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	m := Manifest{
		Version:              "v2",
		MinVersion:           "v1",
		RootFSURL:            srv.URL + "/rootfs",
		RootFSHash:           sha256hex(rootfs),
		KernelcacheURL:       srv.URL + "/kernelcache",
		KernelcacheHash:      sha256hex(kernel),
		FirmwareURL:          srv.URL + "/firmware",
		FirmwareHash:         sha256hex(firmware),
		FirmwareVerityHash:   "abcdef0123456789",
		FirmwareHashTreeURL:  srv.URL + "/firmware-hashtree",
		FirmwareHashTreeHash: sha256hex(firmwareHashTree),
		FirmwareVersion:      5,
		FirmwareMinVersion:   0,
	}
	mData, _ := json.Marshal(m)
	mSig := ed25519.Sign(signPriv, mData)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mData) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(mSig) })
	mux.HandleFunc("/signing-cert.json", func(w http.ResponseWriter, r *http.Request) { w.Write(certBytes) })
	mux.HandleFunc("/signing-cert.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(certSig) })

	wal := newWALFile(t)
	dirs := StageDirs{
		Rootfs:   filepath.Join(t.TempDir(), "rootfs"),
		ESP:      filepath.Join(t.TempDir(), "esp"),
		Firmware: filepath.Join(t.TempDir(), "firmware"),
	}

	msg, err := Stage(context.Background(), wal, srv.URL+"/manifest.json", "", rootPub, dirs)
	if err != nil {
		t.Fatalf("Stage with firmware: %v", err)
	}
	if !strings.Contains(msg, "default v5") {
		t.Errorf("stage message should report the staged firmware bundle: %q", msg)
	}
	// The legacy single-firmware manifest folds into a bundle named "default"; staging
	// activates its slot (next -> active) in the bundle subdir so the next boot mounts it.
	bdir := filepath.Join(dirs.Firmware, "default")
	if _, err := os.Stat(filepath.Join(bdir, "firmware-active.img")); err != nil {
		t.Errorf("firmware not activated: %v", err)
	}
	// The boot trust anchor is persisted beside the image and re-verifies offline to
	// the staged bundle's verity hash, keyed to the same root pubkey the daemon uses.
	hash, ver, err := VerifyFirmwareAnchor(bdir, "active", rootPub, time.Now(), "default")
	if err != nil {
		t.Fatalf("staged firmware anchor does not verify: %v", err)
	}
	if hash != m.FirmwareVerityHash || ver != m.FirmwareVersion {
		t.Errorf("anchor hash/ver = %q/%d, want %q/%d", hash, ver, m.FirmwareVerityHash, m.FirmwareVersion)
	}
	d, _ := deployment.Load(wal)
	if !d.HasPendingFirmware("default") || d.Firmware.Bundle("default").PendingVersion != 5 {
		t.Fatalf("firmware track not pending: %+v", d.Firmware.Bundle("default"))
	}
	// The rootfs track is staged independently and unaffected.
	if d.RootFS.Pending != "v2" {
		t.Fatalf("rootfs track disturbed by firmware staging: %+v", d.RootFS)
	}
}
