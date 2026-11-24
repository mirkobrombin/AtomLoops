package peers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/signing"
)

const testBlock = 64 << 10

type keys struct {
	rootPub []byte
	sign    string
	cert    Bundle
}

func newKeys(t *testing.T) keys {
	t.Helper()
	dir := t.TempDir()
	root, rootPub := filepath.Join(dir, "root.key"), filepath.Join(dir, "root.pub")
	sk, spub := filepath.Join(dir, "signing.key"), filepath.Join(dir, "signing.pub")
	if err := signing.GenerateKeyFiles(root, rootPub); err != nil {
		t.Fatal(err)
	}
	if err := signing.GenerateKeyFiles(sk, spub); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, "cert.json")
	if err := signing.IssueCert(root, cert, sk, 1, 24*time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(rootPub)
	c, _ := os.ReadFile(cert)
	cs, _ := os.ReadFile(cert + ".sig")
	return keys{rootPub: pub, sign: sk, cert: Bundle{Cert: c, CertSig: cs}}
}

func (k keys) release(t *testing.T, version string, image []byte, expires time.Time) Bundle {
	t.Helper()
	dir := t.TempDir()
	img := filepath.Join(dir, "rootfs.erofs")
	os.WriteFile(img, image, 0o644)
	blocks, err := otad.HashBlocks(img, testBlock)
	if err != nil {
		t.Fatal(err)
	}
	m := otad.Manifest{Version: version, RootFSURL: "https://example.invalid/rootfs.erofs",
		RootFSHash: "00", KernelcacheURL: "https://example.invalid/kc.efi", KernelcacheHash: "00", RootFSBlockSize: testBlock, RootFSBlocks: blocks, Expires: expires.UTC().Format(time.RFC3339)}
	data, _ := json.Marshal(m)
	mp := filepath.Join(dir, "manifest.json")
	os.WriteFile(mp, data, 0o644)
	sigPath, err := signing.SignManifest(k.sign, mp)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(sigPath)
	return Bundle{Manifest: data, Sig: sig, Cert: k.cert.Cert, CertSig: k.cert.CertSig}
}

func (k keys) resign(t *testing.T, b Bundle) Bundle {
	t.Helper()
	mp := filepath.Join(t.TempDir(), "manifest.json")
	os.WriteFile(mp, b.Manifest, 0o644)
	sigPath, err := signing.SignManifest(k.sign, mp)
	if err != nil {
		t.Fatal(err)
	}
	b.Sig, _ = os.ReadFile(sigPath)
	return b
}

func image(t *testing.T, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	rand.Read(b)
	return b
}

func serve(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.Serve(ln)
	return ln.Addr().String()
}

func offering(t *testing.T, l Limits, b Bundle, img []byte) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rootfs.erofs")
	os.WriteFile(path, img, 0o644)
	r, err := ReleaseOf(b, path)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(l)
	s.Allow = nil
	s.Offer(r)
	return s, serve(t, s)
}

func dest(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "rootfs-next.erofs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func written(t *testing.T, f *os.File) []byte {
	t.Helper()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func serverFallback(img []byte, used *atomic.Int32) func(ctx context.Context, off int64, n int) ([]byte, error) {
	return func(ctx context.Context, off int64, n int) ([]byte, error) {
		used.Add(1)
		end := min(int64(len(img)), off+int64(n))
		return append([]byte(nil), img[off:end]...), nil
	}
}

func TestNeighboursCarryAWholeRelease(t *testing.T) {
	k := newKeys(t)
	img := image(t, 20*testBlock+1234)
	b := k.release(t, "v12", img, time.Now().Add(time.Hour))
	_, a1 := offering(t, DefaultLimits(), b, img)
	_, a2 := offering(t, DefaultLimits(), b, img)
	plan, err := PlanOf(b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var server atomic.Int32
	f := &Fetcher{Parallel: 4, Fallback: serverFallback(img, &server)}
	out := dest(t)
	res, err := f.Fetch(context.Background(), plan, []string{a1, a2}, out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written(t, out), img) || res.FromPeers != len(plan.Blocks) || server.Load() != 0 || len(res.Dropped) != 0 {
		t.Fatalf("result %+v server %d", res, server.Load())
	}
}

func liar(t *testing.T, sent *atomic.Int32) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
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
					junk := make([]byte, testBlock)
					rand.Read(junk)
					sent.Add(1)
					writeFrame(c, msgData, append(p[:4:4], junk...))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestACorruptNeighbourIsDroppedAndNothingBadIsWritten(t *testing.T) {
	k := newKeys(t)
	img := image(t, 16*testBlock)
	b := k.release(t, "v12", img, time.Now().Add(time.Hour))
	_, good := offering(t, DefaultLimits(), b, img)
	var lies atomic.Int32
	bad := liar(t, &lies)
	plan, _ := PlanOf(b.Manifest)
	var server atomic.Int32
	f := &Fetcher{Parallel: 3, Fallback: serverFallback(img, &server)}
	out := dest(t)
	res, err := f.Fetch(context.Background(), plan, []string{bad, good}, out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written(t, out), img) {
		t.Fatal("a corrupt block reached the disk")
	}
	if len(res.Dropped) != 1 || res.Dropped[0] != bad || lies.Load() == 0 || lies.Load() > 3 {
		t.Fatalf("dropped %v after %d corrupt blocks", res.Dropped, lies.Load())
	}
}

func TestOnlyCorruptNeighboursFallBackToTheServer(t *testing.T) {
	k := newKeys(t)
	img := image(t, 8*testBlock)
	b := k.release(t, "v12", img, time.Now().Add(time.Hour))
	var lies atomic.Int32
	plan, _ := PlanOf(b.Manifest)
	var server atomic.Int32
	f := &Fetcher{Parallel: 2, Fallback: serverFallback(img, &server)}
	out := dest(t)
	res, err := f.Fetch(context.Background(), plan, []string{liar(t, &lies), liar(t, &lies)}, out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written(t, out), img) || res.FromServer != len(plan.Blocks) || len(res.Dropped) != 2 {
		t.Fatalf("result %+v", res)
	}
}

func TestAServerBlockThatDoesNotMatchStopsTheFetch(t *testing.T) {
	k := newKeys(t)
	img := image(t, 4*testBlock)
	b := k.release(t, "v12", img, time.Now().Add(time.Hour))
	plan, _ := PlanOf(b.Manifest)
	f := &Fetcher{Fallback: func(ctx context.Context, off int64, n int) ([]byte, error) { return make([]byte, n), nil }}
	if _, err := f.Fetch(context.Background(), plan, nil, dest(t)); !errors.Is(err, ErrServerBlock) {
		t.Fatalf("got %v", err)
	}
}

func TestASlowNeighbourIsLeftForTheServer(t *testing.T) {
	k := newKeys(t)
	img := image(t, 6*testBlock)
	b := k.release(t, "v12", img, time.Now().Add(time.Hour))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(5 * time.Second); c.Close() }()
		}
	}()
	plan, _ := PlanOf(b.Manifest)
	var server atomic.Int32
	f := &Fetcher{Parallel: 2, BlockTimeout: 200 * time.Millisecond, Fallback: serverFallback(img, &server)}
	out := dest(t)
	start := time.Now()
	res, err := f.Fetch(context.Background(), plan, []string{ln.Addr().String()}, out)
	if err != nil || !bytes.Equal(written(t, out), img) || len(res.Dropped) != 1 {
		t.Fatalf("result %+v %v", res, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("a slow neighbour held the update for %v", time.Since(start))
	}
}

func hello(t *testing.T, addr string, id ID) (byte, error) {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if err := writeFrame(c, msgHello, helloPayload(id)); err != nil {
		return 0, err
	}
	kind, _, err := readFrame(c, maxRelease)
	return kind, err
}

func TestAFloodFromOneAddressIsCappedAndBanned(t *testing.T) {
	k := newKeys(t)
	img := image(t, 2*testBlock)
	b := k.release(t, "v12", img, time.Now().Add(time.Hour))
	l := DefaultLimits()
	s, addr := offering(t, l, b, img)
	plan, _ := PlanOf(b.Manifest)

	var held []net.Conn
	accepted := 0
	for range 200 {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			continue
		}
		held = append(held, c)
		c.SetDeadline(time.Now().Add(500 * time.Millisecond))
		writeFrame(c, msgHello, helloPayload(plan.ID))
		if kind, _, err := readFrame(c, maxRequest); err == nil && kind == msgAccept {
			accepted++
		}
	}
	for _, c := range held {
		c.Close()
	}
	if accepted != l.PerAddress {
		t.Fatalf("one address held %d sessions, the cap is %d", accepted, l.PerAddress)
	}

	time.Sleep(100 * time.Millisecond)
	for range l.StrikesToBan {
		if kind, _ := hello(t, addr, ID{1}); kind != msgRefuse {
			t.Fatalf("an unknown release was answered with %d", kind)
		}
	}
	if !s.Banned("127.0.0.1") {
		t.Fatal("repeated requests for a release nobody has did not ban the address")
	}
	if kind, err := hello(t, addr, plan.ID); err == nil || kind == msgAccept {
		t.Fatalf("a banned address was served: %d %v", kind, err)
	}
}

func TestTheBanGrowsAndExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewServer(DefaultLimits())
	s.Now = func() time.Time { return now }
	for round, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		for range s.Limits.StrikesToBan {
			s.strike("10.0.0.9")
		}
		if !s.Banned("10.0.0.9") {
			t.Fatalf("round %d not banned", round)
		}
		now = now.Add(want - time.Second)
		if !s.Banned("10.0.0.9") {
			t.Fatalf("round %d ban shorter than %v", round, want)
		}
		now = now.Add(2 * time.Second)
		if s.Banned("10.0.0.9") {
			t.Fatalf("round %d ban longer than %v", round, want)
		}
	}
}

func TestUploadIsThrottledAndMetered(t *testing.T) {
	k := newKeys(t)
	img := image(t, 24*testBlock)
	b := k.release(t, "v12", img, time.Now().Add(time.Hour))
	l := DefaultLimits()
	l.UploadRate = 512 << 10
	l.BlocksPerMinute = 1000
	s, addr := offering(t, l, b, img)
	s.bucket = newBucket(l.UploadRate, testBlock)
	plan, _ := PlanOf(b.Manifest)
	f := &Fetcher{Parallel: 4}
	start := time.Now()
	if _, err := f.Fetch(context.Background(), plan, []string{addr}, dest(t)); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	min := time.Duration(float64(len(img)-testBlock) / float64(l.UploadRate) * float64(time.Second))
	if took < min*9/10 {
		t.Fatalf("%d bytes left in %v, the cap allows no less than %v", len(img), took, min)
	}
	if s.Served() != int64(len(img)) {
		t.Fatalf("served %d", s.Served())
	}
}

func TestAPerAddressQuotaStopsAHog(t *testing.T) {
	k := newKeys(t)
	img := image(t, 10*testBlock)
	b := k.release(t, "v12", img, time.Now().Add(time.Hour))
	l := DefaultLimits()
	l.BlocksPerMinute = 4
	_, addr := offering(t, l, b, img)
	plan, _ := PlanOf(b.Manifest)
	var server atomic.Int32
	f := &Fetcher{Parallel: 1, Fallback: serverFallback(img, &server)}
	out := dest(t)
	res, err := f.Fetch(context.Background(), plan, []string{addr}, out)
	if err != nil || !bytes.Equal(written(t, out), img) {
		t.Fatal(err)
	}
	if res.FromPeers != 4 || res.FromServer != 6 {
		t.Fatalf("result %+v", res)
	}
}

func TestNothingIsServedWhileSharingIsOff(t *testing.T) {
	k := newKeys(t)
	img := image(t, 2*testBlock)
	b := k.release(t, "v12", img, time.Now().Add(time.Hour))
	s, addr := offering(t, DefaultLimits(), b, img)
	var on atomic.Bool
	s.Active = on.Load
	plan, _ := PlanOf(b.Manifest)
	if kind, err := hello(t, addr, plan.ID); err == nil || kind == msgAccept {
		t.Fatalf("served while off: %d %v", kind, err)
	}
	on.Store(true)
	if kind, err := hello(t, addr, plan.ID); err != nil || kind != msgAccept {
		t.Fatalf("not served while on: %d %v", kind, err)
	}
}

func TestOnlyNeighboursOnALocalNetworkAreAdmitted(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "127.0.0.1", "203.0.113.7"} {
		if LocalNeighbour(&net.TCPAddr{IP: net.ParseIP(ip)}) {
			t.Errorf("%s admitted", ip)
		}
	}
}

func TestADamagedLocalCopyIsNeverServed(t *testing.T) {
	k := newKeys(t)
	img := image(t, 4*testBlock)
	b := k.release(t, "v12", img, time.Now().Add(time.Hour))
	damaged := append([]byte(nil), img...)
	damaged[testBlock+5] ^= 0xff
	s, addr := offering(t, DefaultLimits(), b, damaged)
	plan, _ := PlanOf(b.Manifest)
	var server atomic.Int32
	f := &Fetcher{Parallel: 1, Fallback: serverFallback(img, &server)}
	out := dest(t)
	res, err := f.Fetch(context.Background(), plan, []string{addr}, out)
	if err != nil || !bytes.Equal(written(t, out), img) {
		t.Fatal(err)
	}
	if res.FromPeers != 1 || res.FromServer != 3 {
		t.Fatalf("result %+v", res)
	}
	if s.Served() != testBlock || s.release(plan.ID) != nil {
		t.Fatalf("the damaged copy sent %d bytes and stayed on offer", s.Served())
	}
}

func TestAReleaseFromANeighbourIsVerified(t *testing.T) {
	k := newKeys(t)
	img := image(t, 2*testBlock)
	fresh := k.release(t, "v12", img, time.Now().Add(time.Hour))
	_, addr := offering(t, DefaultLimits(), fresh, img)
	got, err := AskRelease(context.Background(), nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := VerifyRelease(got, k.rootPub, "v11", time.Now()); err != nil || m.Version != "v12" {
		t.Fatalf("fresh release: %v", err)
	}
	if _, err := VerifyRelease(got, k.rootPub, "v12", time.Now()); !errors.Is(err, ErrStale) {
		t.Fatalf("same release: %v", err)
	}
	expired := k.release(t, "v13", img, time.Now().Add(-time.Minute))
	if _, err := VerifyRelease(expired, k.rootPub, "v11", time.Now()); err == nil {
		t.Fatal("an expired manifest was accepted")
	}
	tampered := got
	tampered.Manifest = bytes.Replace(got.Manifest, []byte("v12"), []byte("v99"), 1)
	if _, err := VerifyRelease(tampered, k.rootPub, "v11", time.Now()); err == nil {
		t.Fatal("a tampered manifest was accepted")
	}
	other := newKeys(t)
	if _, err := VerifyRelease(got, other.rootPub, "v11", time.Now()); err == nil {
		t.Fatal("a release signed under another root was accepted")
	}
}

func TestMalformedFramesAreRefused(t *testing.T) {
	if _, err := decodeBundle([]byte{0, 0, 0, 9, 1}); err == nil {
		t.Fatal("short bundle decoded")
	}
	var buf bytes.Buffer
	head := make([]byte, 5)
	head[0] = msgHello
	binary.BigEndian.PutUint32(head[1:], 1<<30)
	buf.Write(head)
	if _, _, err := readFrame(&buf, maxRequest); err == nil {
		t.Fatal("an oversized frame was read")
	}
	if _, ok := parseHello(append([]byte("SINTY-PEER-0"), make([]byte, 32)...)); ok {
		t.Fatal("wrong magic accepted")
	}
}
