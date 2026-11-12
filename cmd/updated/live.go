package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/mirkobrombin/atomloops/internal/live"
	"github.com/mirkobrombin/atomloops/internal/otad"
)

func (c cfg) dirs() otad.StageDirs {
	return otad.StageDirs{Rootfs: c.rootfsDir, ESP: c.espDir, Firmware: c.firmwareDir}
}

func liveOffer(c cfg, st Status) Status {
	if st.State != "ready" {
		return st
	}
	cand, err := otad.LiveCandidateOf(c.wal, c.dirs(), rootPub)
	if err != nil {
		return st
	}
	offer := cand.Offer
	st.Live = &offer
	return st
}

func applyLive(c cfg, logw io.Writer) (live.Result, error) {
	lock, err := acquireStageLock(c.stageLock)
	if err != nil {
		return live.Result{}, err
	}
	defer releaseStageLock(lock)
	res, err := live.Apply(live.Options{
		WAL:     c.wal,
		Dirs:    c.dirs(),
		RootPub: rootPub,
		PCR:     c.livePCR,
		Logf:    func(f string, a ...any) { fmt.Fprintf(logw, f+"\n", a...) },
	})
	if err != nil {
		return res, err
	}
	statuses := statusStore{statePath: c.state}
	statuses.complete(Status{State: "idle", Current: res.Offer.To, Latest: res.Offer.To})
	if c.history != "" {
		if herr := recordRunning(c.history, runningVersion(c.wal), osRelease("/etc/os-release", "BUILD_ID"), time.Now()); herr != nil {
			fmt.Fprintf(logw, "updated: history %s: %v\n", c.history, herr)
		}
	}
	return res, nil
}

func registerLiveHandlers(mux *http.ServeMux, c cfg, statuses *statusStore) {
	mux.HandleFunc("/apply-live", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if statuses.get().State != "ready" {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, errNoStagedUpdate.Error()), http.StatusConflict)
			return
		}
		res, err := applyLive(c, os.Stderr)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			code := http.StatusConflict
			if errors.Is(err, errStageBusy) {
				code = http.StatusServiceUnavailable
			}
			w.WriteHeader(code)
			json.NewEncoder(w).Encode(struct {
				live.Result
				Error string `json:"error"`
			}{res, err.Error()})
			return
		}
		json.NewEncoder(w).Encode(res)
	})
}

func applyLiveCommand(args []string) int {
	fs := flag.NewFlagSet("apply-live", flag.ExitOnError)
	wal := fs.String("wal", defaultWAL, "deployment WAL path")
	rootfsDir := fs.String("rootfs-dir", "/boot/rootfs", "rootfs slot dir")
	espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "ESP kernelcache slot dir")
	state := fs.String("state", "/run/updated/status.json", "status file the UI reads")
	stageLock := fs.String("stage-lock", "/run/updated-stage.lock", "cross-process update staging lock")
	history := fs.String("history", defaultHistory, "installed version history")
	pcr := fs.Int("live-pcr", 0, "TPM PCR a live swap is measured into (0: none)")
	check := fs.Bool("check", false, "only report whether the staged update can be applied live")
	fs.Parse(args)
	c := cfg{wal: *wal, rootfsDir: *rootfsDir, espDir: *espDir, state: *state, stageLock: *stageLock, history: *history, livePCR: *pcr}
	if *check {
		cand, err := otad.LiveCandidateOf(c.wal, c.dirs(), rootPub)
		if err != nil {
			fmt.Fprintf(os.Stderr, "updated: apply-live: %v\n", err)
			return 1
		}
		b, _ := json.MarshalIndent(cand.Offer, "", "  ")
		fmt.Println(string(b))
		if !cand.Offer.Eligible {
			return 3
		}
		return 0
	}
	res, err := applyLive(c, os.Stderr)
	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))
	if err != nil {
		fmt.Fprintf(os.Stderr, "updated: apply-live: %v\n", err)
		return 1
	}
	return 0
}
