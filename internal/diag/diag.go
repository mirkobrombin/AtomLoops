// Package diag collects a diagnostic bundle when a boot or install fails and
// distills it into a compact report small enough to hand to a QR renderer. The
// full bundle is meant to be written where the user can retrieve it (SINTYLOGS);
// the compact report is the essential failure, sized to fit one QR.
//
// It shells out for sources it cannot read as files (dmesg, failed units), so the
// caller decides what "failed units" means on a given system. Every source is
// best-effort: a missing file or a failing command yields an empty section, never
// an error, because a diagnostic collector must not itself fail on a broken box.
package diag

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// Source is one log input: read Path if set, otherwise run Cmd via sh -c and
// capture stdout. Only the last Max bytes are kept (the tail is the useful part);
// Max <= 0 keeps everything.
type Source struct {
	Label string
	Path  string
	Cmd   string
	Max   int
}

// Config is what to collect for one failure.
type Config struct {
	Stage   string // "boot" or "install"
	Error   string // one-line error the caller already knows (may be empty)
	Sources []Source
}

// DefaultConfig returns the standard Sinty sources. Paths/commands are overridable
// by editing the returned slice before calling Collect.
func DefaultConfig(stage, errLine string) Config {
	return Config{
		Stage: stage,
		Error: errLine,
		Sources: []Source{
			{Label: "cmdline", Path: "/proc/cmdline"},
			{Label: "dmesg", Cmd: "dmesg", Max: 64 << 10},
			{Label: "failed-units", Cmd: "atomctl list-failed"},
			{Label: "session", Path: "/run/atom/boot.log", Max: 32 << 10},
			{Label: "rescue", Path: "/run/sintylogs/rescue.log", Max: 16 << 10},
		},
	}
}

// Section is one collected source.
type Section struct {
	Label string
	Data  []byte
}

// Bundle is everything collected for a failure.
type Bundle struct {
	Stage    string
	Error    string
	When     string
	Sections []Section
}

func tail(b []byte, max int) []byte {
	if max > 0 && len(b) > max {
		return b[len(b)-max:]
	}
	return b
}

// Collect reads every source best-effort. now supplies the timestamp so callers
// (and tests) control it.
func Collect(cfg Config, now func() time.Time) Bundle {
	b := Bundle{Stage: cfg.Stage, Error: cfg.Error, When: now().UTC().Format(time.RFC3339)}
	for _, s := range cfg.Sources {
		var data []byte
		if s.Path != "" {
			data, _ = os.ReadFile(s.Path)
		} else if s.Cmd != "" {
			out, _ := exec.Command("sh", "-c", s.Cmd).Output()
			data = out
		}
		b.Sections = append(b.Sections, Section{Label: s.Label, Data: tail(data, s.Max)})
	}
	return b
}

// ID is a short content id: the first 8 hex chars of the SHA256 of the full
// bundle. It ties a scanned compact report back to the full bundle on disk.
func (b Bundle) ID() string {
	sum := sha256.Sum256(b.Full())
	return hex.EncodeToString(sum[:])[:8]
}

// Full renders the whole bundle as readable text, for writing to SINTYLOGS.
func (b Bundle) Full() []byte {
	var sb strings.Builder
	fmt.Fprintf(&sb, "SINTY-DIAG stage=%s when=%s\n", b.Stage, b.When)
	if b.Error != "" {
		fmt.Fprintf(&sb, "error: %s\n", b.Error)
	}
	for _, s := range b.Sections {
		fmt.Fprintf(&sb, "\n===== %s =====\n", s.Label)
		sb.Write(s.Data)
		if len(s.Data) > 0 && s.Data[len(s.Data)-1] != '\n' {
			sb.WriteByte('\n')
		}
	}
	return []byte(sb.String())
}

func lastLines(b []byte, n int) string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (b Bundle) section(label string) []byte {
	for _, s := range b.Sections {
		if s.Label == label {
			return s.Data
		}
	}
	return nil
}

// Compact returns the essential failure report, small enough for a QR: the stage,
// the error, the kernel cmdline, the failed units, the last dmesgLines of dmesg,
// and the bundle ID so a scan links back to the full log on disk.
func (b Bundle) Compact(dmesgLines int) []byte {
	var sb strings.Builder
	fmt.Fprintf(&sb, "stage: %s\n", b.Stage)
	if b.Error != "" {
		fmt.Fprintf(&sb, "error: %s\n", b.Error)
	}
	fmt.Fprintf(&sb, "id: %s\n", b.ID())
	fmt.Fprintf(&sb, "when: %s\n", b.When)
	if cl := strings.TrimSpace(string(b.section("cmdline"))); cl != "" {
		fmt.Fprintf(&sb, "cmdline: %s\n", cl)
	}
	if fu := strings.TrimSpace(string(b.section("failed-units"))); fu != "" {
		fmt.Fprintf(&sb, "failed: %s\n", strings.Join(strings.Fields(fu), " "))
	}
	if dm := b.section("dmesg"); len(dm) > 0 {
		fmt.Fprintf(&sb, "dmesg-tail:\n%s\n", lastLines(dm, dmesgLines))
	}
	return []byte(sb.String())
}

// EncodeQRPayload wraps a payload for the QR channel: a self-describing header
// line, then base64url of the gzip-compressed payload. A future web tool (or a
// plain decode) splits on the first newline, base64url-decodes, and gunzips.
func EncodeQRPayload(payload []byte) []byte {
	var sb strings.Builder
	sb.WriteString("SINTY-FAIL v1\n")
	sb.WriteString(base64.RawURLEncoding.EncodeToString(gzipBytes(payload)))
	return []byte(sb.String())
}
