package recovery

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/otad"
)

// Drive the menu: show status, then quit. Exercises the loop + Status without
// touching wifi or the network.
func TestTTYStatusThenQuit(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "deployment.json")
	if err := deployment.New("dev", "v1").Save(wal); err != nil {
		t.Fatalf("seed WAL: %v", err)
	}
	core := NewCore(Config{
		Iface:   "wlan0",
		WALPath: wal,
		Dirs:    otad.StageDirs{Rootfs: filepath.Join(dir, "rootfs"), ESP: filepath.Join(dir, "esp")},
	})
	var out strings.Builder
	ui := NewTTY(core, strings.NewReader("4\nq\n"), &out)
	if err := ui.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "Sinty Recovery") {
		t.Errorf("menu header missing")
	}
	if !strings.Contains(s, "current=") {
		t.Errorf("status not printed: %q", s)
	}
}
