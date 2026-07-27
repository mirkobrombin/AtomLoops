package otad

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func TestStatusShowsFirmwareTrack(t *testing.T) {
	d := deployment.New("dev-1", "v1")
	d.Firmware.Bundle("default").StableThreshold = 2
	d.DeployFirmware("default", 5, "feedface")
	wal := filepath.Join(t.TempDir(), "deployment.json")
	if err := d.Save(wal); err != nil {
		t.Fatal(err)
	}
	out, err := Status(wal)
	if err != nil {
		t.Fatal(err)
	}
	// The probe hook keys on "firmware" + "pending"; prove Status emits both so the
	// candidate is observable and the hook can fire.
	if !strings.Contains(out, "firmware[default]") || !strings.Contains(out, "pending v5") {
		t.Errorf("status missing firmware pending line:\n%s", out)
	}
}
