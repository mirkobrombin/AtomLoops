package sealedlog

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const (
	compInit    Component = 4
	compShell   Component = 11
	compSession Component = 22
)

func TestMain(m *testing.M) {
	if err := LoadDictionary([]byte("# test system\n4 sinit init\n11 shell session user\n22 session session user\n")); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestPayloadRoundTrip(t *testing.T) {
	p := Payload{BaseUnixMs: 1762272000123, Records: []Record{
		{Component: CompLoader, Code: LoaderBootStart, Args: []uint64{2, 1}},
		{Component: CompKernelEarly, Code: KernelInitExit, DeltaMs: 4200, Args: []uint64{172, 512}},
		{Component: compInit, Code: CodeReady, DeltaMs: 1},
	}}
	b := p.Encode()
	got, err := DecodePayload(append(b, 0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, p)
	}
	one := AppendRecord(nil, Record{Component: CompKernelEarly, Code: KernelPanic, DeltaMs: 30, Args: []uint64{172}})
	if len(one) > 8 {
		t.Fatalf("a panic record takes %d bytes, want at most 8", len(one))
	}
}

func TestSealOpen(t *testing.T) {
	k := newKey(t)
	h := Header{Seq: 7, Boot: 3, Counter: 41}
	b, err := Seal(k.PublicKey(), h, []byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != BlockSize {
		t.Fatalf("block is %d bytes", len(b))
	}
	gh, pt, err := Open(k, b)
	if err != nil || string(pt) != "payload" || gh != h {
		t.Fatalf("open: %+v %q %v", gh, pt, err)
	}
	if _, _, err := Open(newKey(t), b); err != ErrOpen {
		t.Fatalf("a foreign key opened the block: %v", err)
	}
	b[offBoot]++
	if _, _, err := Open(k, b); err != ErrOpen {
		t.Fatalf("a tampered header still opens: %v", err)
	}
	if _, err := Seal(k.PublicKey(), h, make([]byte, MaxPayload+1), nil); err != ErrTooLarge {
		t.Fatalf("oversize payload: %v", err)
	}
}

func ring(t *testing.T, blocks int) (*Ring, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ring")
	if err := CreateRingFile(p, blocks); err != nil {
		t.Fatal(err)
	}
	r, f, err := OpenRingFile(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return r, p
}

func TestRingWrapsIntoCold(t *testing.T) {
	k := newKey(t)
	r, _ := ring(t, 4)
	cold := Cold{Dir: filepath.Join(t.TempDir(), "cold")}
	r.Archive = cold.Put
	for boot := uint32(1); boot <= 5; boot++ {
		for i := 0; i < 2; i++ {
			p := Payload{Records: []Record{{Component: compInit, Code: CodeStart, Args: []uint64{uint64(boot), uint64(i)}}}}
			if _, err := r.Append(k.PublicKey(), boot, uint64(boot), p.Encode()); err != nil {
				t.Fatal(err)
			}
		}
	}
	hot, err := r.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(hot) != 4 || hot[0].Header.Seq != 7 || hot[3].Header.Seq != 10 {
		t.Fatalf("hot ring holds %d blocks from %d", len(hot), hot[0].Header.Seq)
	}
	if br := Verify(hot); br != nil {
		t.Fatalf("hot chain: %v", br)
	}
	if got := NextBoot(hot); got != 6 {
		t.Fatalf("next boot %d", got)
	}
	archived, err := cold.ReadCold()
	if err != nil {
		t.Fatal(err)
	}
	all := append(archived, hot...)
	if len(all) != 10 {
		t.Fatalf("cold plus hot hold %d blocks, want all 10", len(all))
	}
	if br := Verify(all); br != nil {
		t.Fatalf("full chain: %v", br)
	}
	for _, e := range all {
		_, pt, err := Open(k, e.Raw)
		if err != nil {
			t.Fatal(err)
		}
		p, err := DecodePayload(pt)
		if err != nil || p.Records[0].Args[0] != uint64(e.Header.Boot) {
			t.Fatalf("seq %d: %+v %v", e.Header.Seq, p, err)
		}
	}
}

func TestVerifyCatchesTampering(t *testing.T) {
	k := newKey(t)
	r, p := ring(t, 8)
	for i := 0; i < 3; i++ {
		if _, err := r.Append(k.PublicKey(), 1, 0, []byte{0}); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	forged, err := Seal(k.PublicKey(), Header{Ring: r.ID, Seq: 2, Boot: 1}, []byte{0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(forged, BlockSize); err != nil {
		t.Fatal(err)
	}
	entries, err := r.Scan()
	if err != nil {
		t.Fatal(err)
	}
	br := Verify(entries)
	if len(br) == 0 {
		t.Fatal("a replaced block passed verification")
	}
	if _, err := f.WriteAt(EmptyBlock(r.ID, 1), BlockSize); err != nil {
		t.Fatal(err)
	}
	entries, _ = r.Scan()
	if len(Verify(entries)) != 0 || len(r.Check(entries)) == 0 {
		t.Fatal("a block erased from an unwrapped ring went unnoticed")
	}
}

func TestForeignBlocksIgnored(t *testing.T) {
	k := newKey(t)
	a, _ := ring(t, 4)
	b, pb := ring(t, 4)
	if _, err := a.Append(k.PublicKey(), 1, 0, []byte{0}); err != nil {
		t.Fatal(err)
	}
	ea, _ := a.Scan()
	f, err := os.OpenFile(pb, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt(ea[0].Raw, 0); err != nil {
		t.Fatal(err)
	}
	if eb, _ := b.Scan(); len(eb) != 0 {
		t.Fatal("a block of another ring was taken as ours")
	}
}

func TestMigrateKeepsHotBoots(t *testing.T) {
	k := newKey(t)
	r, _ := ring(t, 16)
	for boot := uint32(1); boot <= 6; boot++ {
		if _, err := r.Append(k.PublicKey(), boot, 0, []byte{0}); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := r.Scan()
	cold := Cold{Dir: filepath.Join(t.TempDir(), "cold"), MaxBytes: 3 * BlockSize}
	if err := cold.Migrate(entries, 2); err != nil {
		t.Fatal(err)
	}
	if err := cold.Migrate(entries, 2); err != nil {
		t.Fatal(err)
	}
	got, _ := cold.ReadCold()
	if len(got) != 3 || got[0].Header.Boot != 2 || got[2].Header.Boot != 4 {
		t.Fatalf("cold after prune: %d blocks", len(got))
	}
}

func TestDictionary(t *testing.T) {
	c, ok := ComponentByName("kernel-early")
	if !ok || c != CompKernelEarly || c.String() != "kernel-early" {
		t.Fatalf("component lookup %v %v", c, ok)
	}
	code, ok := CodeByName(CompKernelEarly, "init-exit")
	if !ok || CodeName(CompKernelEarly, code) != "init-exit" {
		t.Fatalf("code lookup %v %v", code, ok)
	}
	if CodeName(CompLoader, CodeFail) != "fail" {
		t.Fatal("shared code name")
	}
	for c := range components {
		if got, ok := ComponentByName(c.String()); !ok || got != c {
			t.Fatalf("component %d does not round trip", c)
		}
	}
}

func TestCollectorSocket(t *testing.T) {
	k := newKey(t)
	r, _ := ring(t, 32)
	c := &Collector{Ring: r, Reader: k.PublicKey(), Boot: 9, Interval: time.Hour}
	sock := filepath.Join(t.TempDir(), "s")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Serve(ctx, sock) }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := Emit(sock, Record{Component: compSession, Code: SessionLogin, Args: []uint64{3}}); err != nil {
		t.Fatal(err)
	}
	if err := Emit(sock, Record{Component: CompKernelEarly, Code: KernelInitExit, Args: []uint64{172, 512}}); err != nil {
		t.Fatal(err)
	}
	var entries []Entry
	for i := 0; i < 100; i++ {
		entries, _ = r.Scan()
		if len(entries) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("a critical record did not flush: %d blocks", len(entries))
	}
	_, pt, err := Open(k, entries[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := DecodePayload(pt)
	if len(p.Records) != 2 || entries[0].Header.Boot != 9 || p.Records[0].Code != SessionLogin {
		t.Fatalf("collected %+v", p)
	}
	if os.Getuid() >= 1000 {
		if d := p.Records[1]; d.Component != CompLogd || d.Code != CodeDenied || d.Args[1] != uint64(CompKernelEarly) {
			t.Fatalf("a desktop user logged as the kernel: %+v", d)
		}
	} else if p.Records[1].Args[0] != 172 {
		t.Fatalf("collected %+v", p)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCollectorSplitsFullBlocks(t *testing.T) {
	k := newKey(t)
	r, _ := ring(t, 32)
	c := &Collector{Ring: r, Reader: k.PublicKey(), Boot: 1}
	for i := 0; i < 2000; i++ {
		if err := c.Add(Record{Component: compShell, Code: CodeReady, Args: []uint64{uint64(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	entries, _ := r.Scan()
	total := 0
	for _, e := range entries {
		_, pt, err := Open(k, e.Raw)
		if err != nil {
			t.Fatal(err)
		}
		p, err := DecodePayload(pt)
		if err != nil {
			t.Fatal(err)
		}
		total += len(p.Records)
	}
	if total != 2000 || len(entries) < 2 {
		t.Fatalf("%d records in %d blocks", total, len(entries))
	}
}

func TestPolicy(t *testing.T) {
	if !Allowed(0, CompKernelEarly) || !Allowed(999, CompUpdated) {
		t.Fatal("system users must log as any component")
	}
	if Allowed(1001, CompKernelEarly) || !Allowed(1001, compSession) {
		t.Fatal("a desktop user may log only as the session")
	}
}

func TestMapRoundTrip(t *testing.T) {
	m := Map{Ring: [16]byte{1, 2, 3}, PartUUID: "0fc63daf-8483-4772-8e79-3d69d8477de4", Blocks: 4,
		Extents: []Extent{{1 << 20, 2 * BlockSize}, {9 << 20, 2 * BlockSize}}}
	got, err := ParseMap(m.Encode())
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatalf("%+v %v", got, err)
	}
	m.Blocks = 5
	if _, err := ParseMap(m.Encode()); err == nil {
		t.Fatal("a map whose extents do not cover the ring parsed")
	}
}

func TestBlobRecord(t *testing.T) {
	p := Payload{Records: []Record{{Component: CompKernelEarly, Code: CodeBlob, Args: []uint64{uint64(KernelPanic)},
		Blob: []byte("panic: Going nowhere without my init!")}}}
	got, err := DecodePayload(p.Encode())
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestEarlyFromKernel(t *testing.T) {
	dir := t.TempDir()
	old := EFIVarDir
	EFIVarDir = dir
	t.Cleanup(func() { EFIVarDir = old })
	kernel := []byte{7, 0, 0, 0, 7, 0, 0, 0}
	kernel = append(kernel[:4], 0)
	kernel = append(kernel, byte(CompKernelEarly), byte(KernelStage), 1, 0, 1)
	kernel = append(kernel, byte(CompKernelEarly), byte(KernelInitExit), 2, 0xc8, 0x01, 0, 0xac, 0x01)
	if err := os.WriteFile(filepath.Join(dir, VarEarly+"-"+VendorGUID), append([]byte{7, 0, 0, 0}, kernel...), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := ReadEFIVar(VarEarly)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ParseEarly(b)
	if err != nil {
		t.Fatal(err)
	}
	if e.Boot != 7 || len(e.Payload.Records) != 2 {
		t.Fatalf("%+v", e)
	}
	ex := e.Payload.Records[1]
	if ex.Code != KernelInitExit || ex.DeltaMs != 200 || ex.Args[0] != 0 || ex.Args[1] != 172 {
		t.Fatalf("init exit decoded as %+v", ex)
	}
	if err := DeleteEFIVar(VarEarly); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEFIVar(VarEarly); err == nil {
		t.Fatal("variable still there")
	}
}

type fakeTPM struct {
	defined bool
	value   uint64
}

func (f *fakeTPM) run(name string, args ...string) ([]byte, error) {
	switch name {
	case "tpm2_nvdefine":
		f.defined = true
		return nil, nil
	case "tpm2_nvincrement":
		if !f.defined {
			return nil, os.ErrNotExist
		}
		f.value++
		return nil, nil
	case "tpm2_nvread":
		b := make([]byte, 8)
		for i := 0; i < 8; i++ {
			b[7-i] = byte(f.value >> (8 * i))
		}
		return b, nil
	}
	return nil, os.ErrInvalid
}

func TestCounter(t *testing.T) {
	f := &fakeTPM{}
	c := TPMCounter{Run: f.run}
	for want := uint64(1); want <= 3; want++ {
		v, err := c.Increment()
		if err != nil || v != want {
			t.Fatalf("increment %d: %d %v", want, v, err)
		}
	}
	k := newKey(t)
	r, _ := ring(t, 8)
	for boot, ctr := range []uint64{1, 2, 5} {
		if _, err := r.Append(k.PublicKey(), uint32(boot+1), ctr, []byte{0}); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := r.Scan()
	br := Verify(entries)
	if len(br) != 1 || br[0].Seq != 3 {
		t.Fatalf("erased boots not reported: %v", br)
	}
	if !Rollback(entries, 6) || Rollback(entries, 5) {
		t.Fatal("rollback check")
	}
}

func TestReadRingFileReadOnly(t *testing.T) {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	r, p := ring(t, 4)
	if _, err := r.Append(k.PublicKey(), 1, 0, Payload{BaseUnixMs: 1}.Encode()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o444); err != nil {
		t.Fatal(err)
	}
	ro, f, err := ReadRingFile(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := ro.Scan()
	if err != nil || len(got) != 1 || got[0].Header.Boot != 1 {
		t.Fatalf("%d entries, %v", len(got), err)
	}
}

func TestDictionaryFile(t *testing.T) {
	if c, ok := ComponentByName("shell"); !ok || c != compShell || !UserComponent(c) || FamilyOf(c) != FamilySession {
		t.Fatalf("shell: %v %v", c, ok)
	}
	if Critical(Record{Component: compInit, Code: InitUnitFail}) != true {
		t.Fatal("a unit failure of the system init is not critical")
	}
	if err := LoadDictionary([]byte("6 something ota\n")); err == nil {
		t.Fatal("a system redefined atomd")
	}
	if err := LoadDictionary([]byte("40 x nofamily\n")); err == nil {
		t.Fatal("unknown family accepted")
	}
	if Component(77).String() != "component-77" || CodeName(Component(77), CodeLocal) != "code-32" {
		t.Fatal("unknown component not shown by number")
	}
}

func TestEarlyPanicText(t *testing.T) {
	text := "panic: Going nowhere without my init!"
	b := []byte{9, 0, 0, 0, 0}
	b = append(b, byte(CompKernelEarly), byte(KernelPanic), 1, 5, 0x81, 0x01)
	b = append(b, byte(CompKernelEarly), byte(CodeBlob), 1, 0, byte(KernelPanic), byte(len(text)))
	b = append(b, text...)
	e, err := ParseEarly(b)
	if err != nil || e.Boot != 9 || len(e.Payload.Records) != 2 {
		t.Fatalf("%+v %v", e, err)
	}
	r := e.Payload.Records[1]
	if r.Code != CodeBlob || r.Args[0] != uint64(KernelPanic) || string(r.Blob) != text || !Critical(r) {
		t.Fatalf("%+v", r)
	}
}
