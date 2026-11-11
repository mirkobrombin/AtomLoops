package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

type optionalFirmware struct {
	Bundles []otad.OptInOffer `json:"bundles"`
	Message string            `json:"message,omitempty"`
	Error   string            `json:"error,omitempty"`
}

func manifestURL(c cfg) string {
	return strings.TrimRight(c.feed, "/") + "/manifest.json"
}

func listOptionalFirmware(c cfg) ([]otad.OptInOffer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return otad.OptInOffers(ctx, c.wal, manifestURL(c), rootPub)
}

func enableOptionalFirmware(c cfg, name string) (string, error) {
	lock, err := acquireStageLock(c.stageLock)
	if err != nil {
		return "", err
	}
	defer releaseStageLock(lock)
	if err := otad.SetOptIn(otad.OptInPath, name, true); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	msg, err := otad.StageFirmwareBundle(ctx, c.wal, manifestURL(c), rootPub, otad.StageDirs{Firmware: c.firmwareDir}, name)
	if err != nil {
		otad.SetOptIn(otad.OptInPath, name, false)
	}
	return msg, err
}

func disableOptionalFirmware(c cfg, name string) (string, error) {
	lock, err := acquireStageLock(c.stageLock)
	if err != nil {
		return "", err
	}
	defer releaseStageLock(lock)
	if err := otad.SetOptIn(otad.OptInPath, name, false); err != nil {
		return "", err
	}
	if err := otad.RemoveFirmwareBundle(c.wal, otad.StageDirs{Firmware: c.firmwareDir}, name); err != nil {
		return "", err
	}
	return "removed firmware " + name + "; restart to stop using it", nil
}

func registerFirmwareHandlers(mux *http.ServeMux, c cfg) {
	reply := func(w http.ResponseWriter, code int, st optionalFirmware) {
		if st.Bundles == nil {
			st.Bundles = []otad.OptInOffer{}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(st)
	}
	current := func() optionalFirmware {
		b, err := listOptionalFirmware(c)
		st := optionalFirmware{Bundles: b}
		if err != nil {
			st.Error = err.Error()
		}
		return st
	}
	mux.HandleFunc("/firmware/optional", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		st := current()
		code := http.StatusOK
		if st.Error != "" {
			code = http.StatusBadGateway
		}
		reply(w, code, st)
	})
	action := func(path string, run func(cfg, string) (string, error)) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			msg, err := run(c, r.URL.Query().Get("name"))
			if err != nil {
				reply(w, http.StatusConflict, optionalFirmware{Error: err.Error()})
				return
			}
			reply(w, http.StatusOK, optionalFirmware{Message: msg})
		})
	}
	action("/firmware/optional/enable", enableOptionalFirmware)
	action("/firmware/optional/disable", disableOptionalFirmware)
}
