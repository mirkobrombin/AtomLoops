package live

import (
	"errors"
	"fmt"
	"os"

	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/sealedlog"
)

// Options configures Apply.
type Options struct {
	WAL     string
	Dirs    otad.StageDirs
	RootPub []byte
	Store   otad.CounterStore
	PCR     int
	HookDir string
	Anchor  string
	Logf    func(format string, args ...any)
}

// Result reports a live apply.
type Result struct {
	Offer      otad.LiveOffer `json:"offer"`
	Message    string         `json:"message,omitempty"`
	RolledBack bool           `json:"rolled_back,omitempty"`
	Measured   bool           `json:"measured,omitempty"`
}

func emit(code sealedlog.Code) {
	_ = sealedlog.Emit(sealedlog.DefaultSocket, sealedlog.Record{Component: sealedlog.CompAtomd, Code: code})
}

// Apply switches the running root to the staged candidate when its release
// allows it, runs the system hooks, and records the switch as a good boot of
// the candidate. Any failure before the record returns to the previous root.
func Apply(o Options) (Result, error) {
	if o.HookDir == "" {
		o.HookDir = HookDir
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	cand, err := otad.LiveCandidateOf(o.WAL, o.Dirs, o.RootPub)
	if err != nil {
		return Result{}, err
	}
	res := Result{Offer: cand.Offer}
	if !cand.Offer.Eligible {
		return res, fmt.Errorf("not applicable live: %s", cand.Offer.Reason)
	}
	sw, err := Switch(Config{Image: cand.Image, HashTree: cand.HashTree, RootHash: cand.RootHash, Anchor: o.Anchor})
	if err != nil {
		return res, err
	}
	o.Logf("live: switched to %s", cand.Offer.To)
	env := Env{Class: cand.Offer.Class, From: cand.Offer.From, To: cand.Offer.To, OldRoot: sw.OldRoot()}
	prevIdentity, prevErr := os.ReadFile(otad.LiveIdentityPath)
	restoreIdentity := func() {
		if prevErr == nil {
			os.WriteFile(otad.LiveIdentityPath, prevIdentity, 0o644)
		} else {
			os.Remove(otad.LiveIdentityPath)
		}
	}
	fail := func(cause error) (Result, error) {
		restoreIdentity()
		if rerr := sw.Rollback(); rerr != nil {
			return res, errors.Join(cause, fmt.Errorf("rolling back: %w", rerr))
		}
		res.RolledBack = true
		emit(sealedlog.OtaLiveRollback)
		if herr := RunHooks(o.HookDir, "rolledback", env); herr != nil {
			o.Logf("live: %v", herr)
		}
		o.Logf("live: back on %s", cand.Offer.From)
		return res, cause
	}
	if err := RunHooks(o.HookDir, "switched", env); err != nil {
		return fail(err)
	}
	if err := RunHooks(o.HookDir, "health", env); err != nil {
		return fail(err)
	}
	if err := otad.WriteLiveIdentity(cand.Offer.To, cand.RootHash); err != nil {
		return fail(err)
	}
	msg, err := otad.CommitLive(o.WAL, o.Dirs, o.Store)
	if err != nil {
		return fail(err)
	}
	res.Message = msg
	if err := sw.Commit(); err != nil {
		o.Logf("live: %v", err)
	}
	emit(sealedlog.OtaLiveApplied)
	if o.PCR > 0 {
		if err := ExtendPCR(o.PCR, Measurement(cand.Offer.Class, cand.Offer.From, cand.FromHash, cand.Offer.To, cand.RootHash)); err != nil {
			o.Logf("live: measuring the switch into PCR %d: %v", o.PCR, err)
		} else {
			res.Measured = true
		}
	}
	if err := RunHooks(o.HookDir, "committed", env); err != nil {
		o.Logf("live: %v", err)
	}
	return res, nil
}
