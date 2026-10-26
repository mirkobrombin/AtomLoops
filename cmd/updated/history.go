package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultHistory = "/var/lib/updated/history.json"
	historyLimit   = 100
)

type historyEntry struct {
	Version string `json:"version"`
	Build   string `json:"build,omitempty"`
	Time    int64  `json:"time"`
	Success bool   `json:"success"`
}

func readHistory(path string) []historyEntry {
	var entries []historyEntry
	if b, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(b, &entries) != nil {
			entries = nil
		}
	}
	return entries
}

func writeHistory(path string, entries []historyEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func runningVersion(wal string) string {
	if b, err := os.ReadFile(wal); err == nil {
		var d struct {
			RootFS struct {
				Current string `json:"current"`
			} `json:"rootfs"`
		}
		if json.Unmarshal(b, &d) == nil && d.RootFS.Current != "" {
			return d.RootFS.Current
		}
	}
	return ""
}

func osRelease(path, key string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(ln, key+"="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func recordRunning(path, version, build string, now time.Time) error {
	if path == "" || version == "" {
		return nil
	}
	entries := readHistory(path)
	if n := len(entries); n > 0 && entries[n-1].Version == version && entries[n-1].Build == build {
		return nil
	}
	entries = append(entries, historyEntry{Version: version, Build: build, Time: now.Unix(), Success: true})
	if len(entries) > historyLimit {
		entries = entries[len(entries)-historyLimit:]
	}
	return writeHistory(path, entries)
}

func registerHistoryHandler(mux *http.ServeMux, c cfg) {
	mux.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		entries := readHistory(c.history)
		if entries == nil {
			entries = []historyEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Entries []historyEntry `json:"entries"`
		}{entries})
	})
}
