package live

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

// HookDir holds the system's live hooks, read from whichever root is running
// when a phase starts. Each executable is run with the phase as its only
// argument:
//
//	switched    the new root is in place; restart what the update touched
//	health      confirm the system works; any failure rolls the swap back
//	rolledback  the previous root is back; undo what switched did
//	committed   the swap is final
const HookDir = "/usr/lib/atomloops/live.d"

// HookTimeout bounds a single hook.
var HookTimeout = 120 * time.Second

// Env is passed to every hook.
type Env struct {
	Class   string
	From    string
	To      string
	OldRoot string
}

// RunHooks runs every executable of dir for phase, in name order, and stops at
// the first failure. A missing directory runs nothing.
func RunHooks(dir, phase string, env Env) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		ctx, cancel := context.WithTimeout(context.Background(), HookTimeout)
		cmd := exec.CommandContext(ctx, filepath.Join(dir, name), phase)
		cmd.Dir = "/"
		cmd.Env = append(os.Environ(),
			"ATOM_APPLY_CLASS="+env.Class,
			"ATOM_FROM="+env.From,
			"ATOM_TO="+env.To,
			"ATOM_OLD_ROOT="+env.OldRoot,
			"ATOM_LIVE_PHASE="+phase,
		)
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("live hook %s %s: %v: %s", name, phase, err, trim(out))
		}
	}
	return nil
}

func trim(b []byte) string {
	const max = 400
	if len(b) > max {
		b = b[len(b)-max:]
	}
	return string(b)
}
