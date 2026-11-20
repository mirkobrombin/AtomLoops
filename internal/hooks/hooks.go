// Package hooks runs the executables a system drops into one of Atom Loops'
// hook directories, for one phase at a time.
package hooks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

// Timeout bounds a single hook.
var Timeout = 120 * time.Second

// Run runs every executable of dir with phase as its only argument, in name
// order, with env added to the environment, and stops at the first failure.
// A missing directory runs nothing. kind names the hooks in errors.
func Run(kind, dir, phase string, env []string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		info, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		ctx, cancel := context.WithTimeout(context.Background(), Timeout)
		cmd := exec.CommandContext(ctx, filepath.Join(dir, name), phase)
		cmd.Dir = "/"
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("%s hook %s %s: %v: %s", kind, name, phase, err, trim(out))
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
