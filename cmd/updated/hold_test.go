package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePolicy(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHoldDefersFromFirstOffer(t *testing.T) {
	dir := t.TempDir()
	policy := writePolicy(t, dir, `{"updates.defer-days":"3"}`)
	seen := filepath.Join(dir, "seen.json")
	day0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	avail := Status{State: "available", Latest: "v10"}

	st := applyHold(avail, policy, seen, day0)
	if st.State != "held" || st.HeldUntil != day0.AddDate(0, 0, 3).Unix() {
		t.Fatalf("day 0: %+v", st)
	}
	st = applyHold(avail, policy, seen, day0.AddDate(0, 0, 2))
	if st.State != "held" || st.HeldUntil != day0.AddDate(0, 0, 3).Unix() {
		t.Fatalf("day 2 must keep the first offer date: %+v", st)
	}
	if st = applyHold(avail, policy, seen, day0.AddDate(0, 0, 3)); st.State != "available" {
		t.Fatalf("day 3: %+v", st)
	}
	newer := Status{State: "available", Latest: "v11"}
	if st = applyHold(newer, policy, seen, day0.AddDate(0, 0, 3)); st.State != "held" {
		t.Fatalf("a newer release starts its own deferral: %+v", st)
	}
}

func TestHoldWaitsForTheWindow(t *testing.T) {
	dir := t.TempDir()
	policy := writePolicy(t, dir, `{"updates.window":"22:00-04:00"}`)
	seen := filepath.Join(dir, "seen.json")
	avail := Status{State: "available", Latest: "v10"}
	at := func(h, m int) time.Time { return time.Date(2026, 11, 2, h, m, 0, 0, time.Local) }

	st := applyHold(avail, policy, seen, at(15, 30))
	if st.State != "held" || st.HeldUntil != at(22, 0).Unix() {
		t.Fatalf("afternoon: %+v", st)
	}
	for _, now := range []time.Time{at(23, 0), at(1, 0), at(3, 59)} {
		if st = applyHold(avail, policy, seen, now); st.State != "available" {
			t.Fatalf("%v inside the window: %+v", now, st)
		}
	}
	if st = applyHold(avail, policy, seen, at(4, 0)); st.HeldUntil != at(22, 0).Unix() {
		t.Fatalf("window end: %+v", st)
	}
}

func TestHoldDeferralThenWindow(t *testing.T) {
	dir := t.TempDir()
	policy := writePolicy(t, dir, `{"updates.defer-days":"1","updates.window":"02:00-03:00"}`)
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.Local)
	st := applyHold(Status{State: "available", Latest: "v10"}, policy, filepath.Join(dir, "seen.json"), now)
	want := time.Date(2026, 11, 4, 2, 0, 0, 0, time.Local)
	if st.State != "held" || st.HeldUntil != want.Unix() {
		t.Fatalf("got %v want %v", time.Unix(st.HeldUntil, 0), want)
	}
}

func TestHoldIgnoresBadOrMissingPolicy(t *testing.T) {
	dir := t.TempDir()
	avail := Status{State: "available", Latest: "v10"}
	now := time.Now()
	for _, body := range []string{`{}`, `{"updates.defer-days":"soon"}`, `{"updates.window":"25:00-02:00"}`, `{"updates.window":"02:00-02:00"}`, `not json`} {
		if st := applyHold(avail, writePolicy(t, dir, body), filepath.Join(dir, "seen.json"), now); st.State != "available" {
			t.Fatalf("%s: %+v", body, st)
		}
	}
	if st := applyHold(avail, filepath.Join(dir, "absent.json"), filepath.Join(dir, "seen.json"), now); st.State != "available" {
		t.Fatalf("absent: %+v", st)
	}
	if st := applyHold(Status{State: "idle"}, writePolicy(t, dir, `{"updates.defer-days":"5"}`), filepath.Join(dir, "seen.json"), now); st.State != "idle" {
		t.Fatalf("idle: %+v", st)
	}
}
