package recovery

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
	"github.com/mirkobrombin/atomloops/internal/otad"
)

func walWithCandidate(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "deployment.json")
	d := deployment.New("dev-1", "v1")
	d.Deploy("v2") // a pending candidate to roll back from
	// pretend the candidate switched (so current=v2, lkg=v1)
	d.DecrementBootAttempt()
	d.RecordGoodBoot(true)
	if err := d.Save(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRecoveryStatus(t *testing.T) {
	s := New(walWithCandidate(t), "", otad.StageDirs{})
	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status code %d", w.Code)
	}
	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["current"] != "v2" || body["last_known_good"] != "v1" {
		t.Fatalf("status body wrong: %+v", body)
	}
}

func TestRecoveryRollback(t *testing.T) {
	wal := walWithCandidate(t)
	s := New(wal, "", otad.StageDirs{})
	req := httptest.NewRequest("POST", "/rollback", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("rollback code %d", w.Code)
	}
	// The WAL must now be back on last_known_good, no candidate.
	d, _ := deployment.Load(wal)
	if d.RootFS.Current != "v1" || d.HasPending() {
		t.Fatalf("rollback did not return to v1: %+v", d.RootFS)
	}
}
