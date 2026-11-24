package main

import (
	"os"
	"path/filepath"
	"testing"
)

func policyIn(t *testing.T) (neighbourPolicy, string) {
	t.Helper()
	dir := t.TempDir()
	p := neighbourPolicy{off: filepath.Join(dir, "off"), kind: filepath.Join(dir, "kind"), metered: filepath.Join(dir, "metered"), power: filepath.Join(dir, "power")}
	return p, dir
}

func battery(t *testing.T, p neighbourPolicy, status, capacity string) {
	t.Helper()
	dir := filepath.Join(p.power, "BAT0")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "type"), []byte("Battery\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "status"), []byte(status+"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "capacity"), []byte(capacity+"\n"), 0o644)
}

func TestNeighboursNeedAHomeOrWorkNetwork(t *testing.T) {
	p, _ := policyIn(t)
	if p.network() || p.upload() {
		t.Fatal("an unclassified network shares updates")
	}
	for kind, want := range map[string]bool{"home": true, "work": true, "public": false, "": false} {
		os.WriteFile(p.kind, []byte(kind+"\n"), 0o644)
		if p.network() != want || p.upload() != want {
			t.Fatalf("%q network %v upload %v", kind, p.network(), p.upload())
		}
	}
}

func TestTheSwitchMeteredNetworksAndALowBatteryStopSharing(t *testing.T) {
	p, _ := policyIn(t)
	os.WriteFile(p.kind, []byte("home"), 0o644)
	os.WriteFile(p.metered, nil, 0o644)
	if !p.network() || p.upload() {
		t.Fatal("a metered network uploads")
	}
	os.Remove(p.metered)
	battery(t, p, "Discharging", "20")
	if p.upload() {
		t.Fatal("a low battery uploads")
	}
	battery(t, p, "Charging", "20")
	if !p.upload() {
		t.Fatal("a charging laptop does not upload")
	}
	os.WriteFile(p.off, nil, 0o644)
	if p.network() || p.upload() {
		t.Fatal("the switch does not turn sharing off")
	}
}
