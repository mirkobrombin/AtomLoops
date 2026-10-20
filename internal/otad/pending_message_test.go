package otad

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func TestPendingUpdateErrorWhileConfirming(t *testing.T) {
	cmdline := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(cmdline, []byte("ro sing.roothash=abc atom.version=v214\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetBootedCmdlinePath(cmdline)()
	d := &deployment.Deployment{}
	d.RootFS.Pending = "v214"
	d.RootFS.PendingHash = "abc"
	d.Kernelcache.StableBoots = 1
	d.Kernelcache.StableThreshold = 3
	msg := pendingUpdateError(d, "loader").Error()
	if !strings.Contains(msg, "being confirmed (1 of 3 good starts)") {
		t.Fatalf("got %q", msg)
	}
}

func TestPendingUpdateErrorBeforeReboot(t *testing.T) {
	cmdline := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(cmdline, []byte("ro sing.roothash=old atom.version=v213\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetBootedCmdlinePath(cmdline)()
	d := &deployment.Deployment{}
	d.RootFS.Pending = "v214"
	d.RootFS.PendingHash = "abc"
	msg := pendingUpdateError(d, "recovery").Error()
	if msg != "recovery: a system update is waiting for a reboot, finish it first" {
		t.Fatalf("got %q", msg)
	}
}
