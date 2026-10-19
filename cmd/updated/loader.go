package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

var loaderAutoFlag = "/var/lib/sinty/loader-auto"

type loaderStatus struct {
	otad.LoaderStatus
	Available int    `json:"available,omitempty"`
	Auto      bool   `json:"auto"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
}

func loaderAuto() bool {
	_, err := os.Stat(loaderAutoFlag)
	return err == nil
}

func setLoaderAuto(on bool) error {
	if !on {
		if err := os.Remove(loaderAutoFlag); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(loaderAutoFlag), 0o755); err != nil {
		return err
	}
	return os.WriteFile(loaderAutoFlag, []byte("1\n"), 0o644)
}

func stageLoader(c cfg, retry bool) (string, error) {
	lock, err := acquireStageLock(c.stageLock)
	if err != nil {
		return "", err
	}
	defer releaseStageLock(lock)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return otad.StageLoader(ctx, c.wal, strings.TrimRight(c.feed, "/")+"/manifest.json", "", rootPub,
		otad.StageDirs{Rootfs: c.rootfsDir, ESP: c.espDir}, retry)
}

func maybeAutoStageLoader(c cfg, checked Status) {
	if !loaderAuto() || checked.LoaderAvailable == 0 || checked.State != "idle" {
		return
	}
	st := otad.ReadLoaderStatus(otad.StageDirs{ESP: c.espDir})
	if st.Candidate != 0 || checked.LoaderAvailable <= st.Installed || checked.LoaderAvailable == st.Failed {
		return
	}
	stageLoader(c, false)
}

func registerLoaderHandlers(mux *http.ServeMux, c cfg, statuses *statusStore) {
	reply := func(w http.ResponseWriter, code int, st loaderStatus) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(st)
	}
	current := func() loaderStatus {
		return loaderStatus{
			LoaderStatus: otad.ReadLoaderStatus(otad.StageDirs{ESP: c.espDir}),
			Available:    statuses.get().LoaderAvailable,
			Auto:         loaderAuto(),
		}
	}
	mux.HandleFunc("/loader", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		reply(w, http.StatusOK, current())
	})
	mux.HandleFunc("/loader/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		msg, err := stageLoader(c, r.URL.Query().Get("retry") == "1")
		st := current()
		if err != nil {
			st.Error = err.Error()
			reply(w, http.StatusConflict, st)
			return
		}
		st.Message = msg
		reply(w, http.StatusOK, st)
	})
	mux.HandleFunc("/loader/auto", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if err := setLoaderAuto(r.URL.Query().Get("enable") == "1"); err != nil {
			st := current()
			st.Error = err.Error()
			reply(w, http.StatusInternalServerError, st)
			return
		}
		reply(w, http.StatusOK, current())
	})
}
