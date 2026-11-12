package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func TestParseChannelsRejectsBadSpecs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "channel")
	for _, spec := range []string{"stable", "Stable=https://a", "stable=", "a=https://a,a=https://b"} {
		if _, err := parseChannels(spec, file); err == nil {
			t.Fatalf("parseChannels(%q) accepted", spec)
		}
	}
	if _, err := parseChannels("stable=https://a", ""); err == nil {
		t.Fatal("channels without a channel file accepted")
	}
	ch, err := parseChannels("", "")
	if err != nil || len(ch.list) != 0 {
		t.Fatalf("empty spec = %+v, %v", ch, err)
	}
}

func TestChannelSelectionFollowsFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sub", "channel")
	ch, err := parseChannels("stable=https://feed/stable,canary=https://feed/canary", file)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg{feed: "https://fixed", channels: ch}
	if ch.current() != "stable" || c.feedURL() != "https://feed/stable" {
		t.Fatalf("default = %s %s", ch.current(), c.feedURL())
	}
	if err := ch.set("canary"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(file); string(b) != "canary\n" {
		t.Fatalf("channel file = %q", b)
	}
	if c.feedURL() != "https://feed/canary" {
		t.Fatalf("canary feed = %s", c.feedURL())
	}
	if err := ch.set("beta"); err == nil {
		t.Fatal("unknown channel accepted")
	}
	if err := os.WriteFile(file, []byte("beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ch.current() != "stable" {
		t.Fatalf("unknown name in file selects %s", ch.current())
	}
	if err := ch.set("stable"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("default channel left the file behind: %v", err)
	}
	if (cfg{feed: "https://fixed"}).feedURL() != "https://fixed" {
		t.Fatal("no channels must keep the fixed feed")
	}
}

func TestExplicitFeedOverridesChannels(t *testing.T) {
	file := filepath.Join(t.TempDir(), "channel")
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("feed", "https://default", "")
	spec, chFile := channelFlags(fs)
	if err := fs.Parse([]string{"--feed", "https://test", "--channels", "stable=https://s", "--channel-file", file}); err != nil {
		t.Fatal(err)
	}
	if ch := resolveChannels(fs, *spec, *chFile); len(ch.list) != 0 {
		t.Fatalf("explicit --feed kept channels %+v", ch)
	}
	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("feed", "https://default", "")
	spec, chFile = channelFlags(fs)
	if err := fs.Parse([]string{"--channels", "stable=https://s", "--channel-file", file}); err != nil {
		t.Fatal(err)
	}
	if ch := resolveChannels(fs, *spec, *chFile); ch.current() != "stable" {
		t.Fatalf("channels = %+v", ch)
	}
}

func TestChannelEndpointSwitchesFeedAndRechecks(t *testing.T) {
	feed, rp, _, _ := setupFeed(t)
	old := rootPub
	rootPub = rp
	t.Cleanup(func() { rootPub = old })

	work := t.TempDir()
	wal := filepath.Join(work, "deployment.json")
	if err := deployment.New("dev", "v1").Save(wal); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(work, "channel")
	ch, err := parseChannels("stable=http://127.0.0.1:1,canary="+feed, file)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg{current: "v1", wal: wal, channels: ch}
	statuses := statusStore{statePath: filepath.Join(work, "status.json")}
	mux := http.NewServeMux()
	registerChannelHandlers(mux, c, &statuses)

	do := func(method, target string) (int, channelState) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
		var st channelState
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("%s %s: %s", method, target, rec.Body.String())
		}
		return rec.Code, st
	}

	code, st := do(http.MethodGet, "/channel")
	if code != http.StatusOK || st.Channel != "stable" || len(st.Channels) != 2 {
		t.Fatalf("GET = %d %+v", code, st)
	}
	code, st = do(http.MethodPost, "/channel?name=canary")
	if code != http.StatusOK || st.Channel != "canary" {
		t.Fatalf("POST canary = %d %+v", code, st)
	}
	if got := statuses.get(); got.State != "available" || got.Latest != "v2" {
		t.Fatalf("status after switching to canary = %+v", got)
	}
	code, st = do(http.MethodPost, "/channel?name=nightly")
	if code != http.StatusConflict || st.Channel != "canary" || st.Error == "" {
		t.Fatalf("POST unknown = %d %+v", code, st)
	}
	code, st = do(http.MethodPost, "/channel?name=stable")
	if code != http.StatusOK || st.Channel != "stable" {
		t.Fatalf("POST stable = %d %+v", code, st)
	}
	if got := statuses.get(); got.State != "error" {
		t.Fatalf("status after switching back to stable = %+v", got)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/channel", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE = %d", rec.Code)
	}
}
