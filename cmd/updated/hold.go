package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSeen   = "/var/lib/updated/seen.json"
	policyDefer   = "updates.defer-days"
	policyWindow  = "updates.window"
	seenLimit     = 16
	maxDeferDays  = 365
	minutesPerDay = 24 * 60
)

type holdPolicy struct {
	deferDays  int
	windowFrom int
	windowTo   int
	windowSet  bool
}

func readHoldPolicy(path string) holdPolicy {
	var p holdPolicy
	if path == "" {
		return p
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return p
	}
	var values map[string]any
	if json.Unmarshal(b, &values) != nil {
		return p
	}
	if s, ok := values[policyDefer].(string); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			p.deferDays = min(n, maxDeferDays)
		}
	}
	if s, ok := values[policyWindow].(string); ok {
		if from, to, err := parseWindow(s); err == nil {
			p.windowFrom, p.windowTo, p.windowSet = from, to, true
		} else {
			fmt.Fprintf(os.Stderr, "updated: policy %s: %v\n", policyWindow, err)
		}
	}
	return p
}

func parseWindow(s string) (int, int, error) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), "-")
	if !ok {
		return 0, 0, fmt.Errorf("%q is not HH:MM-HH:MM", s)
	}
	from, err := parseClock(a)
	if err != nil {
		return 0, 0, err
	}
	to, err := parseClock(b)
	if err != nil {
		return 0, 0, err
	}
	if from == to {
		return 0, 0, fmt.Errorf("%q is an empty window", s)
	}
	return from, to, nil
}

func parseClock(s string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

func (p holdPolicy) inWindow(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	if p.windowFrom < p.windowTo {
		return m >= p.windowFrom && m < p.windowTo
	}
	return m >= p.windowFrom || m < p.windowTo
}

func (p holdPolicy) windowOpens(t time.Time) time.Time {
	if !p.windowSet || p.inWindow(t) {
		return t
	}
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	opens := day.Add(time.Duration(p.windowFrom) * time.Minute)
	if !opens.After(t) {
		opens = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location()).Add(time.Duration(p.windowFrom) * time.Minute)
	}
	return opens
}

func firstSeen(path, version string, now time.Time) time.Time {
	seen := map[string]int64{}
	if b, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(b, &seen) != nil {
			seen = map[string]int64{}
		}
	}
	if t, ok := seen[version]; ok && t <= now.Unix() {
		return time.Unix(t, 0)
	}
	seen[version] = now.Unix()
	if len(seen) > seenLimit {
		versions := make([]string, 0, len(seen))
		for v := range seen {
			versions = append(versions, v)
		}
		sort.Slice(versions, func(i, j int) bool { return seen[versions[i]] > seen[versions[j]] })
		for _, v := range versions[seenLimit:] {
			delete(seen, v)
		}
	}
	if err := writeSeen(path, seen); err != nil {
		fmt.Fprintf(os.Stderr, "updated: seen %s: %v\n", path, err)
	}
	return now
}

func writeSeen(path string, seen map[string]int64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(seen)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func applyHold(st Status, policy, seen string, now time.Time) Status {
	if st.State != "available" || policy == "" {
		return st
	}
	p := readHoldPolicy(policy)
	if p.deferDays == 0 && !p.windowSet {
		return st
	}
	if seen == "" {
		seen = defaultSeen
	}
	release := now
	if p.deferDays > 0 {
		if t := firstSeen(seen, st.Latest, now).AddDate(0, 0, p.deferDays); t.After(release) {
			release = t
		}
	}
	release = p.windowOpens(release)
	if !release.After(now) {
		return st
	}
	st.State = "held"
	st.HeldUntil = release.Unix()
	return st
}

func holdFlags(fs *flag.FlagSet) (policy, seen *string) {
	policy = fs.String("policy", "", "managed policy file (JSON object of strings) holding "+policyDefer+" and "+policyWindow)
	seen = fs.String("seen", defaultSeen, "when each release was first offered, for deferral")
	return
}

const heldRecheck = 6 * time.Hour

func releaseHeld(c cfg, statuses *statusStore) {
	for {
		changed := statuses.watch.next()
		st := statuses.get()
		if st.State != "held" || st.HeldUntil == 0 {
			<-changed
			continue
		}
		wait := time.Until(time.Unix(st.HeldUntil, 0))
		if wait <= 0 {
			statuses.publishPoll(pollOnce(c))
			continue
		}
		timer := time.NewTimer(min(wait, heldRecheck))
		select {
		case <-changed:
		case <-timer.C:
		}
		timer.Stop()
	}
}
