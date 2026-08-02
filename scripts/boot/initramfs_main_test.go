package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCmdlineValue(t *testing.T) {
	cases := []struct {
		name    string
		cmdline string
		key     string
		want    string
	}{
		{"firmware hash present", "ro quiet ATOM_ROOT_HASH=aaa ATOM_FIRMWARE_HASH=deadbeef", "ATOM_FIRMWARE_HASH", "deadbeef"},
		{"root hash present", "ro ATOM_ROOT_HASH=aaa ATOM_FIRMWARE_HASH=bbb", "ATOM_ROOT_HASH", "aaa"},
		{"firmware absent means empty", "ro quiet ATOM_ROOT_HASH=aaa", "ATOM_FIRMWARE_HASH", ""},
		{"empty cmdline", "", "ATOM_FIRMWARE_HASH", ""},
		{"prefix collision not matched", "ATOM_FIRMWARE_HASH_EXTRA=x", "ATOM_FIRMWARE_HASH", ""},
		{"first field", "ATOM_FIRMWARE_HASH=first ATOM_FIRMWARE_HASH=second", "ATOM_FIRMWARE_HASH", "first"},
		{"tab and multi-space separated", "ro\tATOM_FIRMWARE_HASH=cafe   quiet", "ATOM_FIRMWARE_HASH", "cafe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cmdlineValue(tc.cmdline, tc.key); got != tc.want {
				t.Errorf("cmdlineValue(%q, %q) = %q, want %q", tc.cmdline, tc.key, got, tc.want)
			}
		})
	}
}

func TestRootSlotPairs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "boot", "rootfs")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"active.erofs", "active.hash", "next.erofs", "next.hash", "prev.erofs"} {
		if err := os.WriteFile(filepath.Join(dir, "rootfs-"+name), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}

	pairs := rootSlotPairs(filepath.Dir(filepath.Dir(dir)))
	if len(pairs) != 2 {
		t.Fatalf("rootSlotPairs() returned %d complete pairs, want 2", len(pairs))
	}
	if pairs[0].name != "active" || pairs[1].name != "next" {
		t.Fatalf("rootSlotPairs() order = %q, %q; want active, next", pairs[0].name, pairs[1].name)
	}
}

func TestMapperHasEROFS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mapper")
	data := make([]byte, 1028)
	copy(data[1024:], []byte{0xe2, 0xe1, 0xf5, 0xe0})
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if !mapperHasEROFS(path) {
		t.Fatal("mapperHasEROFS rejected verified EROFS magic")
	}
	data[1024] = 0
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if mapperHasEROFS(path) {
		t.Fatal("mapperHasEROFS accepted invalid magic")
	}
}

func TestFindVerifiedRootSlotSkipsUnreadableMapperAndCleansUp(t *testing.T) {
	pairs := []rootSlotPair{
		{name: "active", data: "active.erofs", hash: "active.hash"},
		{name: "next", data: "next.erofs", hash: "next.hash"},
	}
	var detached []string
	mapperReads := 0
	ops := rootSlotOps{
		attach:      func(path string) string { return "loop:" + path },
		detach:      func(loop string) { detached = append(detached, loop) },
		closeMapper: func() {},
		openMapper:  func(string, string, string) error { return nil },
		mapperHasEROFS: func() bool {
			mapperReads++
			return mapperReads == 2
		},
	}

	opened, reason, ok := findVerifiedRootSlot(pairs, validHash(), ops)
	if !ok || reason != "" || opened.slot.name != "next" {
		t.Fatalf("findVerifiedRootSlot() = slot %q, reason %q, ok %v; want next", opened.slot.name, reason, ok)
	}
	wantDetached := []string{"loop:active.hash", "loop:active.erofs"}
	if !reflect.DeepEqual(detached, wantDetached) {
		t.Fatalf("cleanup detached %v, want %v", detached, wantDetached)
	}
}

func TestFindVerifiedRootSlotCleansUpOpenFailure(t *testing.T) {
	var detached []string
	ops := rootSlotOps{
		attach:         func(path string) string { return "loop:" + path },
		detach:         func(loop string) { detached = append(detached, loop) },
		closeMapper:    func() {},
		openMapper:     func(string, string, string) error { return errors.New("open failed") },
		mapperHasEROFS: func() bool { return true },
	}
	pairs := []rootSlotPair{{name: "active", data: "active.erofs", hash: "active.hash"}}
	if _, _, ok := findVerifiedRootSlot(pairs, validHash(), ops); ok {
		t.Fatal("findVerifiedRootSlot accepted a mapper open failure")
	}
	wantDetached := []string{"loop:active.hash", "loop:active.erofs"}
	if !reflect.DeepEqual(detached, wantDetached) {
		t.Fatalf("cleanup detached %v, want %v", detached, wantDetached)
	}
}

func validHash() string {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

func TestRawRootRequiresUnlock(t *testing.T) {
	cases := []struct {
		name            string
		unlocked        bool
		rootHash        string
		verityAvailable bool
		want            bool
	}{
		{"locked missing hash", false, "", true, false},
		{"locked pending hash", false, "pending", true, false},
		{"locked invalid hash", false, "invalid", true, false},
		{"locked missing veritysetup", false, validHash(), false, false},
		{"unlocked missing hash", true, "", true, true},
		{"unlocked invalid hash", true, "invalid", true, true},
		{"unlocked missing veritysetup", true, validHash(), false, true},
		{"valid locked chain does not use raw", false, validHash(), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := allowRawRoot(tc.unlocked, tc.rootHash, tc.verityAvailable); got != tc.want {
				t.Fatalf("allowRawRoot() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDebugShellRequiresUnlockAndExactLocalConfirmation(t *testing.T) {
	cases := []struct {
		name         string
		unlocked     bool
		confirmation string
		want         bool
	}{
		{"locked exact confirmation", false, "OPEN DEBUG SHELL\n", false},
		{"unlocked no confirmation", true, "", false},
		{"unlocked wrong confirmation", true, "open debug shell\n", false},
		{"unlocked exact confirmation", true, "OPEN DEBUG SHELL\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := debugShellAuthorized(tc.unlocked, tc.confirmation); got != tc.want {
				t.Fatalf("debugShellAuthorized() = %v, want %v", got, tc.want)
			}
		})
	}
}
