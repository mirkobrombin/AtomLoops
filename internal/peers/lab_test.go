package peers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/signing"
)

type labState struct {
	RootPub []byte
	Bundle  Bundle
}

func TestLab(t *testing.T) {
	dir, role := os.Getenv("PEER_LAB"), os.Getenv("PEER_ROLE")
	if dir == "" || role == "" {
		t.Skip("set PEER_LAB and PEER_ROLE to run one device of the network lab")
	}
	img := filepath.Join(dir, "rootfs.erofs")
	report := func(name, format string, args ...any) {
		os.WriteFile(filepath.Join(dir, name), []byte(fmt.Sprintf(format, args...)), 0o644)
	}
	load := func() labState {
		var st labState
		b, err := os.ReadFile(filepath.Join(dir, "state.json"))
		if err != nil || json.Unmarshal(b, &st) != nil {
			t.Fatal("no lab state")
		}
		return st
	}
	until := time.Now().Add(150 * time.Second)
	switch role {
	case "setup":
		data := make([]byte, 10*otad.BlockSize+4321)
		rand.Read(data)
		os.WriteFile(img, data, 0o644)
		k := newKeys(t)
		blocks, err := otad.HashBlocks(img, otad.BlockSize)
		if err != nil {
			t.Fatal(err)
		}
		m := otad.Manifest{Version: "v40", RootFSURL: os.Getenv("PEER_FEED") + "/rootfs.erofs", RootFSHash: "00",
			KernelcacheURL: "https://example.invalid/kc.efi", KernelcacheHash: "00",
			RootFSBlockSize: otad.BlockSize, RootFSBlocks: blocks, Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
		raw, _ := json.Marshal(m)
		mp := filepath.Join(t.TempDir(), "manifest.json")
		os.WriteFile(mp, raw, 0o644)
		sigPath, err := signing.SignManifest(k.sign, mp)
		if err != nil {
			t.Fatal(err)
		}
		sig, _ := os.ReadFile(sigPath)
		out, _ := json.Marshal(labState{RootPub: k.rootPub, Bundle: Bundle{Manifest: raw, Sig: sig, Cert: k.cert.Cert, CertSig: k.cert.CertSig}})
		os.WriteFile(filepath.Join(dir, "state.json"), out, 0o644)
	case "feed":
		data, _ := os.ReadFile(img)
		var ranges atomic.Int32
		srv := &http.Server{Addr: ":8080", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") != "" {
				report("feed.txt", "ranges %d\n", ranges.Add(1))
			}
			http.ServeContent(w, r, "rootfs.erofs", time.Time{}, bytes.NewReader(data))
		})}
		go srv.ListenAndServe()
		time.Sleep(time.Until(until))
	case "holder":
		st := load()
		s := NewServer(DefaultLimits())
		c := NewCarrier(s)
		m, _ := otad.ParseManifest(st.Bundle.Manifest)
		c.Offer(otad.CarriedRelease{Manifest: m, Data: st.Bundle.Manifest, Sig: st.Bundle.Sig, Cert: st.Bundle.Cert, CertSig: st.Bundle.CertSig, Path: img})
		ctx, cancel := context.WithDeadline(context.Background(), until)
		defer cancel()
		go func() {
			for ctx.Err() == nil {
				report("holder-"+os.Getenv("PEER_NAME")+".txt", "served %d banned-flooder %v\n", s.Served(), s.Banned(os.Getenv("PEER_FLOODER")))
				time.Sleep(200 * time.Millisecond)
			}
		}()
		if err := c.Run(ctx, Port); err != nil {
			t.Fatal(err)
		}
	case "liar":
		var lies atomic.Int32
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", Port))
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					if _, _, err := readFrame(c, maxRequest); err != nil {
						return
					}
					writeFrame(c, msgAccept, nil)
					for {
						_, p, err := readFrame(c, maxRequest)
						if err != nil {
							return
						}
						junk := make([]byte, otad.BlockSize)
						rand.Read(junk)
						report("liar.txt", "corrupt blocks sent %d\n", lies.Add(1))
						writeFrame(c, msgData, append(p[:4:4], junk...))
					}
				}()
			}
		}()
		group, err := ListenGroup()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			buf := make([]byte, 512)
			for {
				n, from, err := group.ReadFrom(buf)
				if err != nil {
					return
				}
				if id, ok := parseAsk(buf[:n]); ok {
					group.WriteTo(havePacket(id, Port), from)
				}
			}
		}()
		time.Sleep(time.Until(until))
	case "flood":
		target := net.JoinHostPort(os.Getenv("PEER_TARGET"), fmt.Sprint(Port))
		st := load()
		plan, _ := PlanOf(st.Bundle.Manifest)
		var held []net.Conn
		accepted, refused := 0, 0
		for range 300 {
			c, err := net.DialTimeout("tcp", target, time.Second)
			if err != nil {
				refused++
				continue
			}
			held = append(held, c)
			c.SetDeadline(time.Now().Add(300 * time.Millisecond))
			writeFrame(c, msgHello, helloPayload(plan.ID))
			if kind, _, err := readFrame(c, maxRequest); err == nil && kind == msgAccept {
				accepted++
			} else {
				refused++
			}
		}
		for _, c := range held {
			c.Close()
		}
		time.Sleep(200 * time.Millisecond)
		strikes := 0
		for range 6 {
			c, err := net.DialTimeout("tcp", target, time.Second)
			if err != nil {
				continue
			}
			c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
			c.SetDeadline(time.Now().Add(300 * time.Millisecond))
			buf := make([]byte, 16)
			c.Read(buf)
			c.Close()
			strikes++
		}
		time.Sleep(200 * time.Millisecond)
		c, err := net.DialTimeout("tcp", target, time.Second)
		served := false
		if err == nil {
			c.SetDeadline(time.Now().Add(time.Second))
			writeFrame(c, msgHello, helloPayload(plan.ID))
			kind, _, err := readFrame(c, maxRequest)
			served = err == nil && kind == msgAccept
			c.Close()
		}
		report("flood.txt", "sessions accepted %d of 300, refused %d, garbage sent %d, served after the garbage %v\n", accepted, refused, strikes, served)
	case "fetch":
		st := load()
		if _, err := VerifyRelease(st.Bundle, st.RootPub, "v39", time.Now()); err != nil {
			t.Fatal(err)
		}
		m, _ := otad.ParseManifest(st.Bundle.Manifest)
		c := NewCarrier(NewServer(DefaultLimits()))
		c.Fetcher.BlockTimeout = 5 * time.Second
		out := filepath.Join(dir, "rootfs-next-"+os.Getenv("PEER_NAME")+".erofs")
		var found []string
		discover := c.Discover
		c.Discover = func(ctx context.Context, id ID) ([]string, error) {
			addrs, err := discover(ctx, id)
			found = addrs
			return addrs, err
		}
		start := time.Now()
		err := c.FetchRootFS(context.Background(), otad.CarriedRelease{Manifest: m, Data: st.Bundle.Manifest, Path: out}, out)
		got, _ := os.ReadFile(out)
		want, _ := os.ReadFile(img)
		report("fetch-"+os.Getenv("PEER_NAME")+".txt", "found %v\nerror %v\nidentical %v (%d bytes) in %v\n", found, err, bytes.Equal(got, want), len(got), time.Since(start).Round(time.Millisecond))
		os.Remove(out)
	}
}
