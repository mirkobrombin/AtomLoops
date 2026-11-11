package otad

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func useOptInFile(t *testing.T) string {
	t.Helper()
	old := OptInPath
	OptInPath = filepath.Join(t.TempDir(), "atom", "firmware-optin")
	t.Cleanup(func() { OptInPath = old })
	return OptInPath
}

func optionalBundle(m *Manifest) {
	m.FirmwareBundles = []FirmwareBundleSpec{{
		Name:         "extra",
		URL:          m.FirmwareURL,
		Hash:         m.FirmwareHash,
		VerityHash:   m.FirmwareVerityHash,
		HashTreeURL:  m.FirmwareHashTreeURL,
		HashTreeHash: m.FirmwareHashTreeHash,
		Version:      m.FirmwareVersion,
		OptIn:        true,
	}}
}

func TestOptInRoundTrip(t *testing.T) {
	path := useOptInFile(t)
	if got := OptedIn(path); len(got) != 0 {
		t.Fatalf("missing file: %v", got)
	}
	for _, n := range []string{"b", "a", "b"} {
		if err := SetOptIn(path, n, true); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(path)
	if string(data) != "a\nb\n" {
		t.Fatalf("file %q", data)
	}
	if err := SetOptIn(path, "a", false); err != nil {
		t.Fatal(err)
	}
	if got := OptedIn(path); !got["b"] || got["a"] || len(got) != 1 {
		t.Fatalf("after removal: %v", got)
	}
	for _, bad := range []string{"", "x/y", "x\ny"} {
		if SetOptIn(path, bad, true) == nil {
			t.Errorf("accepted name %q", bad)
		}
	}
}

func TestWanted(t *testing.T) {
	opted := map[string]bool{"chosen": true}
	cases := []struct {
		spec FirmwareBundleSpec
		want bool
	}{
		{FirmwareBundleSpec{Name: "base"}, true},
		{FirmwareBundleSpec{Name: "chosen", OptIn: true}, true},
		{FirmwareBundleSpec{Name: "other", OptIn: true}, false},
	}
	for _, c := range cases {
		if got := c.spec.Wanted(opted); got != c.want {
			t.Errorf("%s: %v, want %v", c.spec.Name, got, c.want)
		}
	}
}

func TestStageSkipsUnchosenOptionalBundle(t *testing.T) {
	useOptInFile(t)
	url, rootPub, _ := firmwareStageServerWith(t, optionalBundle)
	wal := newWALFile(t)
	dirs := StageDirs{
		Rootfs:   filepath.Join(t.TempDir(), "rootfs"),
		ESP:      filepath.Join(t.TempDir(), "esp"),
		Firmware: filepath.Join(t.TempDir(), "firmware"),
	}
	if _, err := Stage(context.Background(), wal, url+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dirs.Firmware, "extra")); !os.IsNotExist(err) {
		t.Fatalf("unchosen bundle downloaded: %v", err)
	}
	d, _ := deployment.Load(wal)
	if _, ok := d.Firmware.Bundles["extra"]; ok {
		t.Fatalf("unchosen bundle recorded: %+v", d.Firmware.Bundles)
	}
}

func TestStageAndRemoveChosenBundle(t *testing.T) {
	path := useOptInFile(t)
	url, rootPub, _ := firmwareStageServerWith(t, optionalBundle)
	wal := newWALFile(t)
	dirs := StageDirs{Firmware: filepath.Join(t.TempDir(), "firmware")}
	if _, err := StageFirmwareBundle(context.Background(), wal, url+"/manifest.json", rootPub, dirs, "missing"); err == nil {
		t.Fatal("staged a bundle the feed does not offer")
	}
	if err := SetOptIn(path, "extra", true); err != nil {
		t.Fatal(err)
	}
	if _, err := StageFirmwareBundle(context.Background(), wal, url+"/manifest.json", rootPub, dirs, "extra"); err != nil {
		t.Fatal(err)
	}
	d, _ := deployment.Load(wal)
	if !d.HasPendingFirmware("extra") {
		t.Fatalf("not pending: %+v", d.Firmware.Bundles["extra"])
	}
	if _, err := os.Stat(filepath.Join(dirs.Firmware, "extra")); err != nil {
		t.Fatal(err)
	}
	if _, err := StageFirmwareBundle(context.Background(), wal, url+"/manifest.json", rootPub, dirs, "extra"); err == nil {
		d, _ = deployment.Load(wal)
		if d.Firmware.Bundles["extra"].MinVersion >= 5 {
			t.Fatal("restaged an installed bundle")
		}
	}
	if err := RemoveFirmwareBundle(wal, dirs, "extra"); err != nil {
		t.Fatal(err)
	}
	d, _ = deployment.Load(wal)
	if _, ok := d.Firmware.Bundles["extra"]; ok {
		t.Fatal("bundle still in the WAL")
	}
	if _, err := os.Stat(filepath.Join(dirs.Firmware, "extra")); !os.IsNotExist(err) {
		t.Fatalf("bundle dir left: %v", err)
	}
	for _, bad := range []string{"", "..", "a/b"} {
		if RemoveFirmwareBundle(wal, dirs, bad) == nil {
			t.Errorf("removed %q", bad)
		}
	}
}

func TestOptInOffers(t *testing.T) {
	wal := newWALFile(t)
	d, _ := deployment.Load(wal)
	b := d.Firmware.Bundle("chosen")
	b.CurrentVersion, b.PendingVersion = 2, 3
	if err := d.Save(wal); err != nil {
		t.Fatal(err)
	}
	m := Manifest{FirmwareBundles: []FirmwareBundleSpec{
		{Name: "base", Version: 1},
		{Name: "chosen", Version: 3, OptIn: true, KernelMin: "7.0", KernelMax: "7.0"},
		{Name: "offered", Version: 4, OptIn: true},
		{Name: "elsewhere", Version: 1, OptIn: true, Chips: []string{"amd"}},
	}}
	got, err := optInOffers(m, wal, nil, "7.1", map[string]bool{"chosen": true})
	if err != nil {
		t.Fatal(err)
	}
	want := []OptInOffer{
		{Name: "chosen", Version: 3, Chosen: true, InstalledVersion: 2, Pending: true, FitsKernel: false},
		{Name: "offered", Version: 4, FitsKernel: true},
	}
	if len(got) != len(want) {
		t.Fatalf("offers %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("offer %d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCoupledKernelCheckIgnoresUnchosenBundles(t *testing.T) {
	path := useOptInFile(t)
	old := FirmwareBundleSpec{Name: "drv", Chips: []string{"amd"}, KernelMin: "1.0", KernelMax: "1.0", OptIn: true}
	m := Manifest{KernelRelease: "99.0", FirmwareBundles: []FirmwareBundleSpec{old}}
	if err := m.CoupledKernelCheck([]string{"amd"}); err != nil {
		t.Fatalf("unchosen bundle gated the update: %v", err)
	}
	if err := SetOptIn(path, "drv", true); err != nil {
		t.Fatal(err)
	}
	if err := m.CoupledKernelCheck([]string{"amd"}); err == nil {
		t.Fatal("chosen bundle without a matching kernel did not gate the update")
	}
}
