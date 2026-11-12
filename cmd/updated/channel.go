package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type channel struct {
	name, feed string
}

type channels struct {
	list []channel
	file string
}

type channelState struct {
	Channel  string   `json:"channel,omitempty"`
	Channels []string `json:"channels"`
	Error    string   `json:"error,omitempty"`
}

var errNoChannels = errors.New("no update channels configured")

func validChannelName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func parseChannels(spec, file string) (channels, error) {
	if spec == "" {
		return channels{}, nil
	}
	if file == "" {
		return channels{}, errors.New("--channels needs --channel-file")
	}
	ch := channels{file: file}
	for _, part := range strings.Split(spec, ",") {
		name, feed, ok := strings.Cut(part, "=")
		if !ok || !validChannelName(name) || feed == "" {
			return channels{}, fmt.Errorf("bad channel %q, want name=url", part)
		}
		if ch.find(name) >= 0 {
			return channels{}, fmt.Errorf("channel %s listed twice", name)
		}
		ch.list = append(ch.list, channel{name: name, feed: feed})
	}
	return ch, nil
}

func (ch channels) find(name string) int {
	for i, c := range ch.list {
		if c.name == name {
			return i
		}
	}
	return -1
}

func (ch channels) current() string {
	if len(ch.list) == 0 {
		return ""
	}
	if b, err := os.ReadFile(ch.file); err == nil {
		if name := strings.TrimSpace(string(b)); ch.find(name) >= 0 {
			return name
		}
	}
	return ch.list[0].name
}

func (ch channels) feed() string {
	if i := ch.find(ch.current()); i >= 0 {
		return ch.list[i].feed
	}
	return ""
}

func (ch channels) names() []string {
	out := make([]string, 0, len(ch.list))
	for _, c := range ch.list {
		out = append(out, c.name)
	}
	return out
}

func (ch channels) set(name string) error {
	if len(ch.list) == 0 {
		return errNoChannels
	}
	if ch.find(name) < 0 {
		return fmt.Errorf("unknown channel %q", name)
	}
	if name == ch.list[0].name {
		if err := os.Remove(ch.file); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(ch.file), 0o755); err != nil {
		return err
	}
	tmp := ch.file + ".new"
	if err := os.WriteFile(tmp, []byte(name+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, ch.file)
}

func (ch channels) state() channelState {
	return channelState{Channel: ch.current(), Channels: ch.names()}
}

func (c cfg) feedURL() string {
	if f := c.channels.feed(); f != "" {
		return f
	}
	return c.feed
}

func channelFlags(fs *flag.FlagSet) (spec, file *string) {
	spec = fs.String("channels", "", "selectable feeds as name=url,name=url; the first is the default")
	file = fs.String("channel-file", "", "file holding the selected channel name")
	return spec, file
}

func resolveChannels(fs *flag.FlagSet, spec, file string) channels {
	explicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "feed" {
			explicit = true
		}
	})
	if explicit {
		return channels{}
	}
	ch, err := parseChannels(spec, file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "updated: %v\n", err)
		os.Exit(2)
	}
	return ch
}

func registerChannelHandlers(mux *http.ServeMux, c cfg, statuses *statusStore) {
	reply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/channel", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			reply(w, http.StatusOK, c.channels.state())
		case http.MethodPost:
			if err := c.channels.set(r.URL.Query().Get("name")); err != nil {
				st := c.channels.state()
				st.Error = err.Error()
				reply(w, http.StatusConflict, st)
				return
			}
			statuses.publishPoll(pollOnce(c))
			reply(w, http.StatusOK, c.channels.state())
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})
}
