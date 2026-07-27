package main

import "testing"

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
