// Package audit is the OTA daemon's append-only update history: one JSON line per
// transition (stage, boot-success/promote, rollback, recovery), so a fleet
// operator can see what a device did and when, and recovery mode can show it.
package audit

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// Event is one recorded transition.
type Event struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

// Append adds one event to the JSONL log at path (created if missing, parent dirs
// assumed to exist). now supplies the timestamp; pass time.Now in production. A
// failed append is returned but is non-fatal to the caller: history is best
// effort, it must never block an update.
func Append(path, action, detail string, now func() time.Time) error {
	e := Event{Time: now().UTC().Format(time.RFC3339), Action: action, Detail: detail}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// Read returns every event in the log (nil if the file is absent). Malformed
// lines are skipped so a torn write can never break the whole history.
func Read(path string) ([]Event, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var events []Event
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var e Event
		if json.Unmarshal([]byte(line), &e) == nil {
			events = append(events, e)
		}
	}
	return events, nil
}
