package live

import "github.com/mirkobrombin/atomloops/internal/hooks"

// HookDir holds the system's live hooks, read from whichever root is running
// when a phase starts. Each executable is run with the phase as its only
// argument:
//
//	switched    the new root is in place; restart what the update touched
//	health      confirm the system works; any failure rolls the swap back
//	rolledback  the previous root is back; undo what switched did
//	committed   the swap is final
const HookDir = "/usr/lib/atomloops/live.d"

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
	return hooks.Run("live", dir, phase, []string{
		"ATOM_APPLY_CLASS=" + env.Class,
		"ATOM_FROM=" + env.From,
		"ATOM_TO=" + env.To,
		"ATOM_OLD_ROOT=" + env.OldRoot,
		"ATOM_LIVE_PHASE=" + phase,
	})
}
