package peers

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

func carried(t *testing.T, b Bundle, path string) otad.CarriedRelease {
	t.Helper()
	m, err := otad.ParseManifest(b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	return otad.CarriedRelease{Manifest: m, Data: b.Manifest, Sig: b.Sig, Cert: b.Cert, CertSig: b.CertSig, Path: path}
}

func TestTheCarrierTakesBlocksFromNeighboursAndTheRestFromTheServer(t *testing.T) {
	k := newKeys(t)
	img := image(t, 12*testBlock+77)
	var ranges atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			ranges.Add(1)
		}
		http.ServeContent(w, r, "rootfs.erofs", time.Time{}, bytes.NewReader(img))
	}))
	defer srv.Close()
	b := k.release(t, "v20", img, time.Now().Add(time.Hour))
	b.Manifest = bytes.Replace(b.Manifest, []byte("https://example.invalid/rootfs.erofs"), []byte(srv.URL+"/rootfs.erofs"), 1)
	b = k.resign(t, b)

	good := filepath.Join(t.TempDir(), "rootfs-active.erofs")
	os.WriteFile(good, img, 0o644)
	holder := NewCarrier(NewServer(DefaultLimits()))
	holder.Server.Allow = nil
	holder.Offer(carried(t, b, good))
	goodAddr := serve(t, holder.Server)
	var lies atomic.Int32
	bad := liar(t, &lies)

	fetching := NewCarrier(NewServer(DefaultLimits()))
	fetching.Discover = func(ctx context.Context, id ID) ([]string, error) { return []string{bad, goodAddr}, nil }
	out := filepath.Join(t.TempDir(), "rootfs-next.erofs")
	if err := fetching.FetchRootFS(context.Background(), carried(t, b, out), out); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, img) {
		t.Fatal("the carried image differs")
	}
	if holder.Server.Served() == 0 {
		t.Fatal("the neighbour served nothing")
	}
	if err := fetching.FetchRootFS(context.Background(), carried(t, b, out), out); err != ErrNoNeighbours {
		t.Fatalf("a second search inside a minute ran: %v", err)
	}
}

func TestTheCarrierFallsBackWhenNobodyAnswers(t *testing.T) {
	k := newKeys(t)
	b := k.release(t, "v20", image(t, 2*testBlock), time.Now().Add(time.Hour))
	c := NewCarrier(NewServer(DefaultLimits()))
	c.Discover = func(ctx context.Context, id ID) ([]string, error) { return nil, nil }
	out := filepath.Join(t.TempDir(), "x")
	if err := c.FetchRootFS(context.Background(), carried(t, b, out), out); err != ErrNoNeighbours {
		t.Fatalf("got %v", err)
	}
}

func TestFetchRangeAsksForExactlyOneBlock(t *testing.T) {
	img := image(t, 3*testBlock)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "x", time.Time{}, bytes.NewReader(img))
	}))
	defer srv.Close()
	got, err := otad.FetchRange(context.Background(), srv.URL, testBlock, testBlock)
	if err != nil || !bytes.Equal(got, img[testBlock:2*testBlock]) {
		t.Fatalf("%d bytes, %v", len(got), err)
	}
	last, err := otad.FetchRange(context.Background(), srv.URL, 2*testBlock+10, testBlock)
	if err != nil || !bytes.Equal(last, img[2*testBlock+10:]) {
		t.Fatalf("tail %d bytes, %v", len(last), err)
	}
}

func TestTheResponderAnswersSparinglyAndNeverAmplifies(t *testing.T) {
	k := newKeys(t)
	img := image(t, testBlock)
	b := k.release(t, "v20", img, time.Now().Add(time.Hour))
	s, _ := offering(t, DefaultLimits(), b, img)
	now := time.Unix(5000, 0)
	r := NewResponder(s, Port)
	r.Allow = nil
	r.Now = func() time.Time { return now }
	plan, _ := PlanOf(b.Manifest)
	ask := askPacket(plan.ID)
	ip := net.ParseIP("192.168.1.20")
	reply := r.answer(ask, ip)
	if reply == nil || len(reply) >= len(ask) {
		t.Fatalf("reply %d bytes for a %d byte question", len(reply), len(ask))
	}
	if id, port, ok := parseHave(reply); !ok || id != plan.ID || port != Port {
		t.Fatal("bad reply")
	}
	if r.answer(ask, ip) != nil {
		t.Fatal("the same asker was answered twice inside the window")
	}
	if r.answer(askPacket(ID{9}), net.ParseIP("192.168.1.21")) != nil {
		t.Fatal("a release this device does not have was answered")
	}
	if r.answer(ask[:40], net.ParseIP("192.168.1.22")) != nil {
		t.Fatal("a short question was answered")
	}
	answered := 0
	for i := range 100 {
		if r.answer(ask, net.IPv4(10, 0, 1, byte(i))) != nil {
			answered++
		}
	}
	if answered != r.PerSec-1 {
		t.Fatalf("a storm of 100 questions got %d answers in a second that had already answered once, the cap is %d", answered, r.PerSec)
	}
	now = now.Add(11 * time.Second)
	if r.answer(ask, ip) == nil {
		t.Fatal("the asker was never answered again")
	}
	s.Active = func() bool { return false }
	if r.answer(ask, net.ParseIP("192.168.1.99")) != nil {
		t.Fatal("answered while sharing is off")
	}
}

func TestDiscoveryOverARealSocket(t *testing.T) {
	k := newKeys(t)
	img := image(t, testBlock)
	b := k.release(t, "v20", img, time.Now().Add(time.Hour))
	s, _ := offering(t, DefaultLimits(), b, img)
	group, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	r := NewResponder(s, 4242)
	r.Allow = nil
	go r.Serve(group)
	asker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer asker.Close()
	plan, _ := PlanOf(b.Manifest)
	addrs, id, err := Find(context.Background(), asker, group.LocalAddr(), ID{}, 700*time.Millisecond)
	if err != nil || len(addrs) != 1 || addrs[0] != "127.0.0.1:4242" || id != plan.ID {
		t.Fatalf("found %v %x %v", addrs, id[:4], err)
	}
}
