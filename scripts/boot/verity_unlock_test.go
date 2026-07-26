package main

import (
	"errors"
	"testing"
)

// TestUnlockGrantsNoVerity pins the fail-closed rule: dm-verity is skipped ONLY
// when both sintykey reads succeed AND report unlocked + verity off. Every other
// combination, including any read error, must keep verity enforced.
func TestUnlockGrantsNoVerity(t *testing.T) {
	tpmDown := errors.New("sintykey: TPM unreachable")
	cases := []struct {
		name             string
		lockOut          string
		lockErr          error
		verOut           string
		verErr           error
		wantSkip         bool
	}{
		{"unlocked and verity off", "locked=false\nunlock_count=1\n", nil, "verity=off\n", nil, true},
		{"locked and verity off", "locked=true\nunlock_count=0\n", nil, "verity=off\n", nil, false},
		{"unlocked and verity on", "locked=false\nunlock_count=1\n", nil, "verity=on\n", nil, false},
		{"locked and verity on", "locked=true\n", nil, "verity=on\n", nil, false},
		{"lock read error fails closed", "locked=false\n", tpmDown, "verity=off\n", nil, false},
		{"verity read error fails closed", "locked=false\n", nil, "verity=off\n", tpmDown, false},
		{"both empty no error", "", nil, "", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unlockGrantsNoVerity(tc.lockOut, tc.lockErr, tc.verOut, tc.verErr); got != tc.wantSkip {
				t.Errorf("unlockGrantsNoVerity() = %v, want %v", got, tc.wantSkip)
			}
		})
	}
}
