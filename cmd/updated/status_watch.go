package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

var statusWaitLimit = 5 * time.Minute

type statusWatch struct {
	mu      sync.Mutex
	changed chan struct{}
}

func (w *statusWatch) next() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.changed == nil {
		w.changed = make(chan struct{})
	}
	return w.changed
}

func (w *statusWatch) notify() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.changed != nil {
		close(w.changed)
		w.changed = nil
	}
}

func statusTag(st Status) string {
	st.Tag = ""
	b, _ := json.Marshal(clientStatus(st))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func waitForStatus(r *http.Request, watch *statusWatch, current func() Status) (Status, bool) {
	st := current()
	known := r.URL.Query().Get("wait")
	if known == "" {
		return st, true
	}
	limit := time.NewTimer(statusWaitLimit)
	defer limit.Stop()
	for statusTag(st) == known {
		changed := watch.next()
		if st = current(); statusTag(st) != known {
			break
		}
		select {
		case <-changed:
			st = current()
		case <-limit.C:
			return st, true
		case <-r.Context().Done():
			return st, false
		}
	}
	return st, true
}
