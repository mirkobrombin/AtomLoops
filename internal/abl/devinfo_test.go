package abl

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeDevinfo(t *testing.T, dir string, major, minor uint16, flagsA, flagsB byte) string {
	t.Helper()
	b := make([]byte, 8192)
	le := binary.LittleEndian
	le.PutUint32(b, devinfoMagic)
	le.PutUint16(b[4:], major)
	le.PutUint16(b[6:], minor)
	for i := 8; i < len(b); i++ {
		if i < devinfoSlots || i >= devinfoSlots+2*devinfoSlotSize {
			b[i] = byte(i * 7)
		}
	}
	b[devinfoSlots] = 3
	b[devinfoSlots+devinfoFlags] = flagsA
	b[devinfoSlots+devinfoSlotSize] = 3
	b[devinfoSlots+devinfoSlotSize+devinfoFlags] = flagsB
	p := filepath.Join(dir, "sdd5")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func diff(a, b []byte) []int {
	var out []int
	for i := range a {
		if a[i] != b[i] {
			out = append(out, i)
		}
	}
	return out
}

func TestMarkDevinfoSuccessfulTouchesOnlyTheSlotFlag(t *testing.T) {
	p := fakeDevinfo(t, t.TempDir(), 3, 15, 0x04, 0x00)
	before, _ := os.ReadFile(p)
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	changed, err := MarkDevinfoSuccessful(f, 0)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	after, _ := os.ReadFile(p)
	if d := diff(before, after); len(d) != 1 || d[0] != devinfoSlots+devinfoFlags || after[d[0]] != 0x06 {
		t.Fatalf("changed bytes %v, flag now %#x", d, after[devinfoSlots+devinfoFlags])
	}
	changed, err = MarkDevinfoSuccessful(f, 0)
	if err != nil || changed {
		t.Fatalf("second mark changed=%v err=%v", changed, err)
	}
}

func TestMarkDevinfoSuccessfulRefusesAnUnverifiedLayout(t *testing.T) {
	p := fakeDevinfo(t, t.TempDir(), 3, 14, 0x04, 0x00)
	before, _ := os.ReadFile(p)
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := MarkDevinfoSuccessful(f, 0); err == nil || !strings.Contains(err.Error(), "3.14") {
		t.Fatalf("err = %v, want a layout refusal", err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("an unverified layout was written")
	}
}

func TestMarkDevinfoSlotFindsThePartitionAndTheBootedSlot(t *testing.T) {
	root := t.TempDir()
	sys := filepath.Join(root, "sys")
	dev := filepath.Join(root, "dev")
	for _, d := range []string{filepath.Join(sys, "sda", "sda1"), filepath.Join(sys, "sdd", "sdd5"), dev} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(sys, "sda", "sda1", "uevent"), []byte("MAJOR=8\nPARTNAME=userdata\nDEVTYPE=partition\n"), 0o644)
	os.WriteFile(filepath.Join(sys, "sdd", "sdd5", "uevent"), []byte("MAJOR=8\nPARTNAME=devinfo\nDEVTYPE=partition\n"), 0o644)
	os.WriteFile(filepath.Join(dev, "sdd"), nil, 0o600)
	p := fakeDevinfo(t, dev, 3, 15, 0x00, 0x04)
	bootconfig := filepath.Join(root, "bootconfig")
	os.WriteFile(bootconfig, []byte("androidboot.hardware = \"cheetah\"\nandroidboot.slot_suffix = \"_b\"\n"), 0o644)

	msg, err := markDevinfoSlot(sys, dev, bootconfig)
	if err != nil {
		t.Fatal(err)
	}
	if msg != "marked boot slot b successful in sdd5" {
		t.Fatalf("msg = %q", msg)
	}
	b, _ := os.ReadFile(p)
	if b[devinfoSlots+devinfoSlotSize+devinfoFlags] != 0x06 || b[devinfoSlots+devinfoFlags] != 0x00 {
		t.Fatalf("slot flags a=%#x b=%#x", b[devinfoSlots+devinfoFlags], b[devinfoSlots+devinfoSlotSize+devinfoFlags])
	}
}

func TestBootedSlotNeedsTheSuffix(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bootconfig")
	os.WriteFile(p, []byte("androidboot.hardware = \"cheetah\"\n"), 0o644)
	if _, err := bootedSlot(p); err == nil {
		t.Fatal("a bootconfig without a slot suffix gave a slot")
	}
}
