package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fetchStatus(t *testing.T, url string) Status {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func statusServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state.json")
	srv := httptest.NewServer(newUpdateServer(cfg{state: state}).Handler)
	t.Cleanup(srv.Close)
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(state); err == nil {
			return srv, state
		}
	}
	t.Fatal("the startup check never settled the state")
	return srv, state
}

func TestStatusWaitWakesOnStateFileWrite(t *testing.T) {
	srv, state := statusServer(t)
	first := fetchStatus(t, srv.URL+"/status")
	if first.Tag == "" {
		t.Fatal("status carries no tag")
	}
	got := make(chan Status, 1)
	go func() { got <- fetchStatus(t, srv.URL+"/status?wait="+first.Tag) }()
	select {
	case st := <-got:
		t.Fatalf("wait returned before any change: %+v", st)
	case <-time.After(300 * time.Millisecond):
	}
	if err := writeState(state, Status{State: "available", Current: "v1", Latest: "v2"}); err != nil {
		t.Fatal(err)
	}
	select {
	case st := <-got:
		if st.State != "available" || st.Tag == first.Tag {
			t.Fatalf("wait returned a stale status: %+v", st)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("wait did not wake on a state file write")
	}
}

func TestStatusWaitAnswersAStaleTagAtOnce(t *testing.T) {
	srv, _ := statusServer(t)
	start := time.Now()
	st := fetchStatus(t, srv.URL+"/status?wait=0000")
	if time.Since(start) > time.Second || st.Tag == "" {
		t.Fatalf("stale tag not answered at once: %+v after %v", st, time.Since(start))
	}
}

func TestStatusWaitEndsAtTheLimit(t *testing.T) {
	old := statusWaitLimit
	statusWaitLimit = 200 * time.Millisecond
	t.Cleanup(func() { statusWaitLimit = old })
	srv, _ := statusServer(t)
	first := fetchStatus(t, srv.URL+"/status")
	start := time.Now()
	st := fetchStatus(t, srv.URL+"/status?wait="+first.Tag)
	if st.Tag != first.Tag || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("limit not honoured: %+v after %v", st, time.Since(start))
	}
}

func TestStatusWaitWakesOnProgress(t *testing.T) {
	var s statusStore
	s.live = Status{State: "downloading"}
	changed := s.watch.next()
	s.setProgress(10, 100)
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("progress did not notify")
	}
	changed = s.watch.next()
	s.setProgress(10, 100)
	select {
	case <-changed:
		t.Fatal("unchanged progress notified")
	case <-time.After(100 * time.Millisecond):
	}
}
