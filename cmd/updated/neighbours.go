package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/peers"
)

type neighbourPolicy struct {
	off, kind, metered, power string
}

var defaultNeighbourPolicy = neighbourPolicy{
	off:     "/var/lib/sinty-updates/neighbours-off",
	kind:    "/run/sinty-nm/network-kind",
	metered: "/run/sinty-nm/metered",
	power:   "/sys/class/power_supply",
}

func (p neighbourPolicy) network() bool {
	if _, err := os.Stat(p.off); err == nil {
		return false
	}
	b, err := os.ReadFile(p.kind)
	if err != nil {
		return false
	}
	kind := strings.TrimSpace(string(b))
	return kind == "home" || kind == "work"
}

func (p neighbourPolicy) upload() bool {
	if !p.network() {
		return false
	}
	if _, err := os.Stat(p.metered); err == nil {
		return false
	}
	return !p.lowBattery()
}

func (p neighbourPolicy) lowBattery() bool {
	supplies, _ := os.ReadDir(p.power)
	for _, s := range supplies {
		dir := filepath.Join(p.power, s.Name())
		if read(filepath.Join(dir, "type")) != "Battery" || read(filepath.Join(dir, "status")) != "Discharging" {
			continue
		}
		if n, err := strconv.Atoi(read(filepath.Join(dir, "capacity"))); err == nil && n < 30 {
			return true
		}
	}
	return false
}

func read(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

var carrier *peers.Carrier

func (p neighbourPolicy) setEnabled(on bool) error {
	if on {
		if err := os.Remove(p.off); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p.off), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p.off, nil, 0o644)
}

type neighbourState struct {
	Enabled bool  `json:"enabled"`
	Network bool  `json:"network"`
	Upload  bool  `json:"upload"`
	Served  int64 `json:"served"`
}

func (p neighbourPolicy) state() neighbourState {
	_, err := os.Stat(p.off)
	st := neighbourState{Enabled: err != nil, Network: p.network(), Upload: p.upload()}
	if carrier != nil {
		st.Served = carrier.Server.Served()
	}
	return st
}

func registerNeighbourHandlers(mux *http.ServeMux, p neighbourPolicy) {
	mux.HandleFunc("/neighbours", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
		case http.MethodPost:
			if err := p.setEnabled(r.URL.Query().Get("enable") == "1"); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p.state())
	})
}

func startNeighbours(ctx context.Context, c cfg, p neighbourPolicy) *peers.Carrier {
	s := peers.NewServer(peers.DefaultLimits())
	s.Active = p.upload
	carrier = peers.NewCarrier(s)
	carrier.Allowed = p.network
	for _, r := range otad.CarriedReleases(c.wal, otad.StageDirs{Rootfs: c.rootfsDir, ESP: c.espDir}) {
		carrier.Offer(r)
	}
	otad.Carrier = carrier
	go func() {
		if err := carrier.Run(ctx, peers.Port); err != nil {
			fmt.Fprintf(os.Stderr, "updated: neighbours: %v\n", err)
		}
	}()
	return carrier
}
