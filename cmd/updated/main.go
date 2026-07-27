// Command updated is the Sinty OS update agent. It polls the signed update feed
// (updates.sinty.dev), verifies the chain root -> signing-cert -> manifest, compares
// the advertised version against the installed one, and reports a small Status the
// desktop shell consumes (the dock update icon + the Store "Aggiornamenti" tab) over a
// local unix socket. Nothing is trusted by transport: a forged feed is rejected by
// signature, so the manifest may live on any cheap/static host.
//
//	updated check  --feed URL [--current V]        one-shot: print the status JSON
//	updated serve  --feed URL --socket P [--current V] [--interval D]   daemon + API
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "embed"

	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

//go:embed root.pub
var rootPub []byte

// Status is the shape the UI polls. State drives the dock icon:
// idle (no badge) | available (download badge) | downloading (progress bar) |
// ready (green check, offer reboot) | error.
type Status struct {
	State   string `json:"state"`
	Current string `json:"current"`
	Latest  string `json:"latest"`
	Percent int    `json:"percent"`
	Error   string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: updated check|serve ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check":
		fs := flag.NewFlagSet("check", flag.ExitOnError)
		feed := fs.String("feed", "https://updates.sinty.dev/stable", "update feed base URL")
		cur := fs.String("current", "", "installed version (default: read deployment)")
		fs.Parse(os.Args[2:])
		st := check(*feed, *cur)
		b, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(b))
		if st.State == "error" {
			os.Exit(1)
		}
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		feed := fs.String("feed", "https://updates.sinty.dev/stable", "update feed base URL")
		sock := fs.String("socket", "/run/updated.sock", "unix socket for the UI")
		cur := fs.String("current", "", "installed version (default: read deployment)")
		interval := fs.Duration("interval", 6*time.Hour, "poll interval")
		wal := fs.String("wal", "/var/lib/atom/deployment.json", "deployment WAL path")
		rootfsDir := fs.String("rootfs-dir", "/boot/rootfs", "rootfs slot staging dir")
		espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "ESP kernelcache staging dir")
		firmwareDir := fs.String("firmware-dir", "/boot/firmware", "firmware add-on track staging dir")
		fs.Parse(os.Args[2:])
		serve(cfg{feed: *feed, sock: *sock, current: *cur, interval: *interval, wal: *wal, rootfsDir: *rootfsDir, espDir: *espDir, firmwareDir: *firmwareDir})
	default:
		fmt.Fprintln(os.Stderr, "usage: updated check|serve ...")
		os.Exit(2)
	}
}

func fetchBytes(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// verifiedManifest fetches and verifies the feed's manifest against the embedded ROOT
// key (root -> signing-cert -> manifest). Returns the parsed manifest only if every
// signature checks out.
func verifiedManifest(feed string) (otad.Manifest, error) {
	feed = strings.TrimRight(feed, "/")
	get := func(name string) ([]byte, error) { return fetchBytes(feed + "/" + name) }

	certData, err := get("signing-cert.json")
	if err != nil {
		return otad.Manifest{}, err
	}
	certSig, err := get("signing-cert.json.sig")
	if err != nil {
		return otad.Manifest{}, err
	}
	signingPub, _, err := trust.VerifyCert(certData, certSig, rootPub, time.Now())
	if err != nil {
		return otad.Manifest{}, fmt.Errorf("signing cert: %w", err)
	}
	mData, err := get("manifest.json")
	if err != nil {
		return otad.Manifest{}, err
	}
	mSig, err := get("manifest.json.sig")
	if err != nil {
		return otad.Manifest{}, err
	}
	if !trust.Verify(mData, mSig, signingPub) {
		return otad.Manifest{}, fmt.Errorf("manifest signature invalid -- refusing")
	}
	return otad.ParseManifest(mData)
}

func check(feed, current string) Status {
	if current == "" {
		current = installedVersion()
	}
	m, err := verifiedManifest(feed)
	if err != nil {
		return Status{State: "error", Current: current, Error: err.Error()}
	}
	st := Status{Current: current, Latest: m.Version, State: "idle"}
	if newer(m.Version, current) {
		st.State = "available"
	}
	return st
}

// installedVersion reads the running rootfs version from the deployment WAL if present,
// else falls back to os-release VERSION_ID, else "unknown".
func installedVersion() string {
	if b, err := os.ReadFile("/var/lib/atom/deployment.json"); err == nil {
		var d struct {
			RootFS struct {
				Current string `json:"current"`
			} `json:"rootfs"`
		}
		if json.Unmarshal(b, &d) == nil && d.RootFS.Current != "" {
			return d.RootFS.Current
		}
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(ln, "VERSION_ID="); ok {
				return strings.Trim(v, `"`)
			}
		}
	}
	return "unknown"
}

// newer reports whether version a is strictly newer than b, comparing the trailing
// integer (v2 > v1). If either lacks a numeric tail, falls back to string inequality.
func newer(a, b string) bool {
	na, oka := versionNum(a)
	nb, okb := versionNum(b)
	if oka && okb {
		return na > nb
	}
	return a != b && a > b
}

func versionNum(v string) (int, bool) {
	i := len(v)
	for i > 0 && v[i-1] >= '0' && v[i-1] <= '9' {
		i--
	}
	if i == len(v) {
		return 0, false
	}
	n, err := strconv.Atoi(v[i:])
	return n, err == nil
}

type cfg struct {
	feed, sock, current    string
	interval               time.Duration
	wal, rootfsDir, espDir string
	firmwareDir            string
}

// stage fetches + verifies + stages the candidate via otad.Stage, which arms the ESP
// boot-state so the next reboot boots the -next slot. On success the UI offers "restart".
func stage(c cfg, onProgress otad.ProgressFunc) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	ctx = otad.WithProgress(ctx, onProgress)
	return otad.Stage(ctx, c.wal, strings.TrimRight(c.feed, "/")+"/manifest.json", "", rootPub,
		otad.StageDirs{Rootfs: c.rootfsDir, ESP: c.espDir, Firmware: c.firmwareDir})
}

// serve polls the feed and serves the Status over the unix socket for the desktop UI
// (the dock update icon + the Store tab), plus /download and /reboot the UI drives.
func serve(c cfg) {
	var mu sync.Mutex
	latest := check(c.feed, c.current)
	get := func() Status { mu.Lock(); defer mu.Unlock(); return latest }
	set := func(s Status) { mu.Lock(); latest = s; mu.Unlock() }
	poll := func() {
		s := check(c.feed, c.current)
		mu.Lock()
		if latest.State != "downloading" && latest.State != "ready" {
			latest = s // don't clobber an in-flight download
		}
		mu.Unlock()
	}
	download := func() {
		s := get()
		if s.State != "available" {
			return
		}
		set(Status{State: "downloading", Current: s.Current, Latest: s.Latest})
		onProg := func(done, total int64) {
			if total <= 0 {
				return
			}
			mu.Lock()
			if latest.State == "downloading" {
				latest.Percent = int(done * 100 / total)
			}
			mu.Unlock()
		}
		if _, err := stage(c, onProg); err != nil {
			set(Status{State: "error", Current: s.Current, Latest: s.Latest, Error: err.Error()})
			return
		}
		set(Status{State: "ready", Current: s.Current, Latest: s.Latest, Percent: 100})
	}

	os.Remove(c.sock)
	ln, err := net.Listen("unix", c.sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "updated: listen %s: %v\n", c.sock, err)
		os.Exit(1)
	}
	os.Chmod(c.sock, 0o660)

	go func() {
		t := time.NewTicker(c.interval)
		defer t.Stop()
		for range t.C {
			poll()
		}
	}()

	writeJSON := func(w http.ResponseWriter, s Status) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, get()) })
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) { poll(); writeJSON(w, get()) })
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		go download()
		writeJSON(w, get())
	})
	mux.HandleFunc("/reboot", func(w http.ResponseWriter, r *http.Request) {
		if get().State != "ready" {
			http.Error(w, `{"error":"no staged update to reboot into"}`, http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		go func() {
			syscall.Sync()
			syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
		}()
	})
	fmt.Fprintf(os.Stderr, "updated: serving %s (feed %s, poll %s)\n", c.sock, c.feed, c.interval)
	http.Serve(ln, mux)
}
