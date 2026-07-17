package main

import "testing"

func TestVersionNum(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		ok   bool
	}{
		{"v1", 1, true}, {"v2", 2, true}, {"v10", 10, true},
		{"2026.07", 7, true}, {"stable-3", 3, true},
		{"latest", 0, false}, {"", 0, false}, {"v", 0, false},
	}
	for _, c := range cases {
		n, ok := versionNum(c.in)
		if n != c.n || ok != c.ok {
			t.Errorf("versionNum(%q) = (%d,%v), want (%d,%v)", c.in, n, ok, c.n, c.ok)
		}
	}
}

func TestNewer(t *testing.T) {
	// numeric tail wins, and v10 must beat v9 (not string-compare)
	if !newer("v2", "v1") {
		t.Error("v2 should be newer than v1")
	}
	if !newer("v10", "v9") {
		t.Error("v10 should be newer than v9 (numeric, not lexical)")
	}
	if newer("v1", "v2") {
		t.Error("v1 must not be newer than v2")
	}
	if newer("v2", "v2") {
		t.Error("equal versions are not newer")
	}
	// non-numeric falls back to string inequality, never a false 'newer' on equal
	if newer("stable", "stable") {
		t.Error("equal non-numeric must not be newer")
	}
}
