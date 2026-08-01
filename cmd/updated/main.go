// Command updated is the Sinty OS update agent. It checks the signed update feed
// (updates.sinty.dev), verifies the chain root -> signing-cert -> manifest, compares
// the advertised version against the installed one, and reports a small Status the
// desktop shell consumes (the dock update icon + the Store "Aggiornamenti" tab) over a
// local unix socket. Nothing is trusted by transport: a forged feed is rejected by
// signature, so the manifest may live on any cheap/static host. `updated serve`
// checks once at startup, and a dedicated .timer keeps the status fresh.
//
//	updated check --feed URL [--current V]              one-shot: print status JSON
//	updated poll  --feed URL --state P                  check + write state
//	updated serve --feed URL --socket P --state P       socket responder for the UI
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "embed"

	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

// Committed root.pub is a dev placeholder; the deployment build injects its real
// trust root over this file before compiling (see os atomloops.mk).
//
//go:embed root.pub
var rootPub []byte

// defaultWAL is the deployment WAL on the system partition, beside the rootfs slot
// files it describes. It must stay the same file atomd promotes from and the
// initramfs reads at boot: a stager writing one WAL and a promoter reading another
// means a staged update is never seen.
const defaultWAL = "/boot/rootfs/deployment.json"

// Status is the shape the UI polls. State drives the dock icon:
// idle (no badge) | available (download badge) | downloading (progress bar) |
// ready (green check, offer reboot) | error.
type Status struct {
	State          string `json:"state"`
	Current        string `json:"current"`
	Latest         string `json:"latest"`
	ProductName    string `json:"product_name,omitempty"`
	ProductVersion string `json:"product_version,omitempty"`
	ProductBuild   string `json:"product_build,omitempty"`
	ConsentToken   string `json:"consent_token,omitempty"`
	Percent        int    `json:"percent"`
	Error          string `json:"error,omitempty"`
	manifestSHA256 string
	retryable      bool
}

type transientFeedError struct{ err error }

func (e transientFeedError) Error() string { return e.err.Error() }
func (e transientFeedError) Unwrap() error { return e.err }

func clientStatus(status Status) Status {
	status.ConsentToken = ""
	if status.State != "available" || status.manifestSHA256 == "" {
		return status
	}
	sum := sha256.Sum256([]byte("sinty-update-consent-v1:" + status.manifestSHA256))
	status.ConsentToken = hex.EncodeToString(sum[:])
	return status
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: updated check|poll|serve ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check":
		fs := flag.NewFlagSet("check", flag.ExitOnError)
		feed := fs.String("feed", "https://updates.sinty.dev/stable", "update feed base URL")
		cur := fs.String("current", "", "installed version (default: read deployment)")
		wal := fs.String("wal", defaultWAL, "deployment WAL path")
		fs.Parse(os.Args[2:])
		st := check(*feed, *cur, *wal)
		b, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(b))
		if st.State == "error" {
			os.Exit(1)
		}
	case "poll":
		fs := flag.NewFlagSet("poll", flag.ExitOnError)
		feed := fs.String("feed", "https://updates.sinty.dev/stable", "update feed base URL")
		cur := fs.String("current", "", "installed version (default: read deployment)")
		state := fs.String("state", "/run/updated/status.json", "status file the UI reads")
		fs.Bool("no-fetch", false, "deprecated; polling never downloads")
		wal := fs.String("wal", defaultWAL, "deployment WAL path")
		rootfsDir := fs.String("rootfs-dir", "/boot/rootfs", "rootfs slot staging dir")
		espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "ESP kernelcache staging dir")
		firmwareDir := fs.String("firmware-dir", "/boot/firmware", "firmware add-on track staging dir")
		stageLock := fs.String("stage-lock", "/run/updated-stage.lock", "cross-process update staging lock")
		fs.Parse(os.Args[2:])
		c := cfg{feed: *feed, current: *cur, state: *state, wal: *wal, rootfsDir: *rootfsDir, espDir: *espDir, firmwareDir: *firmwareDir, stageLock: *stageLock}
		statuses := statusStore{statePath: c.state}
		st, err := statuses.publishPoll(pollOnce(c))
		if err != nil {
			fmt.Fprintf(os.Stderr, "updated: write state %s: %v\n", c.state, err)
		}
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
		state := fs.String("state", "/run/updated/status.json", "status file written by `updated poll`")
		wal := fs.String("wal", defaultWAL, "deployment WAL path")
		rootfsDir := fs.String("rootfs-dir", "/boot/rootfs", "rootfs slot staging dir")
		espDir := fs.String("esp-dir", "/boot/efi/EFI/atom", "ESP kernelcache staging dir")
		firmwareDir := fs.String("firmware-dir", "/boot/firmware", "firmware add-on track staging dir")
		stageLock := fs.String("stage-lock", "/run/updated-stage.lock", "cross-process update staging lock")
		fs.Parse(os.Args[2:])
		c := cfg{feed: *feed, sock: *sock, current: *cur, state: *state, wal: *wal, rootfsDir: *rootfsDir, espDir: *espDir, firmwareDir: *firmwareDir, stageLock: *stageLock}
		if err := serve(c); err != nil {
			fmt.Fprintf(os.Stderr, "updated: serve: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: updated check|poll|serve ...")
		os.Exit(2)
	}
}

func fetchBytes(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, transientFeedError{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("%s: status %d", url, resp.StatusCode)
		if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, transientFeedError{err: err}
		}
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, transientFeedError{err: err}
	}
	return b, nil
}

// verifiedManifest fetches and verifies the feed's manifest against the embedded ROOT
// key (root -> signing-cert -> manifest). Returns the parsed manifest only if every
// signature checks out.
func verifiedManifest(feed string) (otad.Manifest, string, error) {
	feed = strings.TrimRight(feed, "/")
	get := func(name string) ([]byte, error) { return fetchBytes(feed + "/" + name) }

	certData, err := get("signing-cert.json")
	if err != nil {
		return otad.Manifest{}, "", err
	}
	certSig, err := get("signing-cert.json.sig")
	if err != nil {
		return otad.Manifest{}, "", err
	}
	signingPub, _, err := trust.VerifyCert(certData, certSig, rootPub, time.Now())
	if err != nil {
		return otad.Manifest{}, "", fmt.Errorf("signing cert: %w", err)
	}
	mData, err := get("manifest.json")
	if err != nil {
		return otad.Manifest{}, "", err
	}
	mSig, err := get("manifest.json.sig")
	if err != nil {
		return otad.Manifest{}, "", err
	}
	if !trust.Verify(mData, mSig, signingPub) {
		return otad.Manifest{}, "", fmt.Errorf("manifest signature invalid -- refusing")
	}
	m, err := otad.ParseManifest(mData)
	if err != nil {
		return otad.Manifest{}, "", err
	}
	return m, fmt.Sprintf("%x", sha256.Sum256(mData)), nil
}

func check(feed, current, wal string) Status {
	if current == "" {
		current = installedVersion(wal)
	}
	m, manifestSHA256, err := verifiedManifest(feed)
	if err != nil {
		var transient transientFeedError
		return Status{State: "error", Current: current, Error: err.Error(), retryable: errors.As(err, &transient)}
	}
	st := Status{
		Current: current, Latest: m.Version, State: "idle",
		ProductName: m.ProductName, ProductVersion: m.ProductVersion, ProductBuild: m.ProductBuild,
		manifestSHA256: manifestSHA256,
	}
	if newer(m.Version, current) {
		st.State = "available"
	}
	return st
}

// installedVersion reads the running rootfs version from the deployment WAL if present,
// else falls back to os-release VERSION_ID, else "unknown".
func installedVersion(wal string) string {
	if wal == "" {
		wal = defaultWAL
	}
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
	feed, sock, current, state string
	wal, rootfsDir, espDir     string
	firmwareDir                string
	stageLock                  string
}

// pollOnce checks the feed without downloading or staging artifacts.
func pollOnce(c cfg) Status { return check(c.feed, c.current, c.wal) }

// writeState atomically writes the status file (temp + rename). Empty path is a no-op.
func writeState(path string, s Status) error {
	if path == "" {
		return nil
	}
	if dir := filepath.Dir(path); dir != "" {
		os.MkdirAll(dir, 0o755)
	}
	stored := struct {
		Status
		ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	}{Status: s, ManifestSHA256: s.manifestSHA256}
	b, _ := json.MarshalIndent(stored, "", "  ")
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readState reads the status file. ok is false if it is absent or unparseable.
func readState(path string) (Status, bool) {
	if path == "" {
		return Status{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Status{}, false
	}
	stored := struct {
		Status
		ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	}{}
	if json.Unmarshal(b, &stored) != nil {
		return Status{}, false
	}
	stored.Status.manifestSHA256 = stored.ManifestSHA256
	return stored.Status, true
}

var errStageBusy = errors.New("another update is already being staged")
var errNoStagedUpdate = errors.New("no staged update to reboot into")

func acquireStageLock(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("update staging lock path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create update lock directory: %w", err)
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open update staging lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errStageBusy
		}
		return nil, fmt.Errorf("lock update staging: %w", err)
	}
	return lock, nil
}

func releaseStageLock(lock *os.File) {
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

// stage fetches + verifies + stages the candidate via otad.Stage while holding
// the lock shared with any other staging process.
func stage(c cfg, expectedManifestSHA256 string, onProgress otad.ProgressFunc) (string, error) {
	lock, err := acquireStageLock(c.stageLock)
	if err != nil {
		return "", err
	}
	defer func() {
		releaseStageLock(lock)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	ctx = otad.WithProgress(ctx, onProgress)
	return otad.StageExpectedManifest(ctx, c.wal, strings.TrimRight(c.feed, "/")+"/manifest.json", "", rootPub,
		otad.StageDirs{Rootfs: c.rootfsDir, ESP: c.espDir, Firmware: c.firmwareDir}, expectedManifestSHA256)
}

type statusStore struct {
	mu         sync.Mutex
	statePath  string
	live       Status
	advertised Status
}

func (s *statusStore) currentLocked() Status {
	if s.live.State == "downloading" {
		return s.live
	}
	if status, ok := readState(s.statePath); ok {
		return status
	}
	return Status{State: "idle"}
}

func (s *statusStore) get() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentLocked()
}

func (s *statusStore) getForClient() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := s.currentLocked()
	s.advertiseLocked(status)
	return status
}

func (s *statusStore) advertise(status Status) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advertiseLocked(status)
	return status
}

func (s *statusStore) advertiseLocked(status Status) {
	if status.State == "available" {
		s.advertised = status
		return
	}
	s.advertised = Status{}
}

func (s *statusStore) claimDownload(consentToken string) (Status, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := s.advertised
	if status.State != "available" || consentToken == "" || clientStatus(status).ConsentToken != consentToken {
		return s.currentLocked(), false
	}
	s.advertised = Status{}
	s.live = status
	s.live.State = "downloading"
	s.live.Percent = 0
	s.live.Error = ""
	return status, true
}

func (s *statusStore) setProgress(done, total int64) {
	if total <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live.State == "downloading" {
		s.live.Percent = int(done * 100 / total)
	}
}

func (s *statusStore) complete(status Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = writeState(s.statePath, status)
	s.live = Status{}
}

func (s *statusStore) publishPoll(status Status) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live.State == "downloading" {
		return s.live, nil
	}
	if current, ok := readState(s.statePath); ok && current.State == "ready" {
		return current, nil
	}
	return status, writeState(s.statePath, status)
}

func claimReboot(c cfg, statuses *statusStore) (*os.File, error) {
	lock, err := acquireStageLock(c.stageLock)
	if err != nil {
		return nil, err
	}
	if statuses.get().State != "ready" {
		releaseStageLock(lock)
		return nil, errNoStagedUpdate
	}
	return lock, nil
}

func listenSocket(path string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("update socket path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket path %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		os.Remove(path)
		return nil, err
	}
	return ln, nil
}

// newUpdateServer serves status plus the download and reboot actions the UI drives.
// The first signed feed check starts only after serve has bound the socket.
func newUpdateServer(c cfg) *http.Server {
	statuses := statusStore{statePath: c.state}
	download := func(s Status) {
		onProg := func(done, total int64) {
			statuses.setProgress(done, total)
		}
		done := s
		done.State = "ready"
		done.Percent = 100
		done.Error = ""
		if _, err := stage(c, s.manifestSHA256, onProg); err != nil {
			if errors.Is(err, errStageBusy) {
				done.State = "downloading"
				done.Percent = 0
			} else {
				done.State = "error"
				done.Percent = 0
				done.Error = err.Error()
			}
		}
		statuses.complete(done)
	}

	writeJSON := func(w http.ResponseWriter, s Status) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(clientStatus(s))
	}
	requireMethod := func(w http.ResponseWriter, r *http.Request, method string) bool {
		if r.Method == method {
			return true
		}
		w.Header().Set("Allow", method)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return false
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, statuses.getForClient())
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		st, err := statuses.publishPoll(pollOnce(c))
		if err != nil {
			st.State = "error"
			st.Error = err.Error()
		}
		writeJSON(w, statuses.advertise(st))
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		query, queryErr := url.ParseQuery(r.URL.RawQuery)
		token := ""
		if values, ok := query["token"]; queryErr == nil && ok && len(query) == 1 && len(values) == 1 {
			token = values[0]
		}
		if st, ok := statuses.claimDownload(token); ok {
			go download(st)
			writeJSON(w, statuses.get())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(clientStatus(statuses.get()))
	})
	mux.HandleFunc("/reboot", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		lock, err := claimReboot(c, &statuses)
		if err != nil {
			message := errNoStagedUpdate.Error()
			if errors.Is(err, errStageBusy) {
				message = errStageBusy.Error()
			}
			http.Error(w, fmt.Sprintf(`{"error":%q}`, message), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		go func() {
			syscall.Sync()
			if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART); err != nil {
				releaseStageLock(lock)
			}
		}()
	})
	go startupCheck(c, &statuses, 5*time.Second)
	return &http.Server{Handler: mux}
}

// startupCheck retries initial signed checks briefly while networking settles.
// Scheduled refreshes remain owned by updated-check.timer.
func startupCheck(c cfg, statuses *statusStore, retryDelay time.Duration) {
	const attempts = 3
	for attempt := 0; attempt < attempts; attempt++ {
		checked := pollOnce(c)
		_, err := statuses.publishPoll(checked)
		if err != nil || checked.State != "error" || !checked.retryable {
			return
		}
		if attempt+1 < attempts {
			time.Sleep(retryDelay)
		}
	}
}

// serve creates the unix socket before any network work, then starts the responder.
func serve(c cfg) error {
	ln, err := listenSocket(c.sock)
	if err != nil {
		return fmt.Errorf("listen %s: %w", c.sock, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "updated: serving %s (feed %s)\n", c.sock, c.feed)
	return newUpdateServer(c).Serve(ln)
}
