// Command sealedlogd keeps the sealed boot and session log of Atom Loops.
//
//	sealedlogd serve  [--state D] [--esp-dir D] [--cold D] [--socket S] [--keep N]
//	                                   collect records for the running boot
//	sealedlogd claim  [--key F]        become the reader: the key stays in the
//	                                   caller's home, the collector gets the public half
//	sealedlogd emit   COMPONENT EVENT [ARG...]
//	                                   send one record to the collector
//	sealedlogd read   [--key F] [--boots N]
//	                                   open and print the log
//	sealedlogd keygen --pub F          new reader key, private hex on stdout
//
// The ring is created on first start, pinned on the data filesystem, and
// described to the loader on the ESP. Until a desktop user claims it, the
// collector keeps the records of the running boot in memory.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mirkobrombin/atomloops/internal/sealedlog"
)

const (
	defaultState  = "/var/lib/sealedlog"
	defaultCold   = "/var/log/sealedlog"
	defaultEspDir = "/boot/efi/EFI/atom"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sealedlogd serve|claim|emit|read|keygen ...")
		return 2
	}
	cmd, rest := args[0], args[1:]
	if b, err := os.ReadFile(sealedlog.DefaultDictionary); err == nil {
		if err := sealedlog.LoadDictionary(b); err != nil {
			fmt.Fprintln(os.Stderr, "sealedlogd:", err)
		}
	}
	var err error
	switch cmd {
	case "keygen":
		err = keygen(rest)
	case "claim":
		err = claim(rest)
	case "serve":
		err = serve(rest)
	case "emit":
		err = emit(rest)
	case "read":
		err = read(rest)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sealedlogd:", err)
		return 1
	}
	return 0
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	pub := fs.String("pub", "", "where to write the 32-byte public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pub == "" {
		return errors.New("--pub is required")
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*pub, k.PublicKey().Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(k.Bytes()))
	return nil
}

// prepare creates the ring on first start and keeps the loader map on the
// ESP in step with it.
func prepare(state, espDir string, blocks int) (string, error) {
	ring := filepath.Join(state, "ring")
	if _, err := os.Stat(ring); os.IsNotExist(err) {
		if err := sealedlog.CreateRingFile(ring, blocks); err != nil {
			return ring, err
		}
	}
	m, err := sealedlog.MapFile(ring)
	if err != nil {
		return ring, err
	}
	enc := m.Encode()
	dst := filepath.Join(espDir, "sealedlog.map")
	if cur, err := os.ReadFile(dst); err != nil || !bytes.Equal(cur, enc) {
		if err := writeAtomic(dst, enc); err != nil {
			return ring, err
		}
	}
	return ring, nil
}

func publishPub(state, espDir string, pub []byte) error {
	if err := writeAtomic(filepath.Join(state, "reader.pub"), pub); err != nil {
		return err
	}
	dst := filepath.Join(espDir, "sealedlog.pub")
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, pub) {
		return nil
	}
	return writeAtomic(dst, pub)
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	state := fs.String("state", defaultState, "ring, reader key and owner")
	espDir := fs.String("esp-dir", defaultEspDir, "ESP atom dir the loader reads")
	blocks := fs.Int("blocks", 512, "ring size in 4 KiB blocks, used when the ring is created")
	coldDir := fs.String("cold", defaultCold, "archive of the boots that left the ring")
	coldMax := fs.Int64("cold-max", 64<<20, "archive size bound in bytes")
	socket := fs.String("socket", sealedlog.DefaultSocket, "collector socket")
	keep := fs.Int("keep", 8, "hot boots kept in the ring")
	interval := fs.Duration("interval", 30*time.Second, "flush interval for routine records")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ringPath, perr := prepare(*state, *espDir, *blocks)
	ring, f, err := sealedlog.OpenRingFile(ringPath)
	if err != nil {
		return err
	}
	defer f.Close()
	cold := sealedlog.Cold{Dir: *coldDir, MaxBytes: *coldMax}
	ring.Archive = cold.Put
	entries, err := ring.Scan()
	if err != nil {
		return err
	}
	efiErr := sealedlog.MountEFIVars()
	boot := sealedlog.NextBoot(entries)
	fromLoader := false
	if lb, ok := sealedlog.ReadLoaderBoot(); ok {
		for _, e := range entries {
			if e.Header.Seq == lb.Seq && e.Header.Boot == lb.Boot {
				boot, fromLoader = lb.Boot, true
			}
		}
	}
	c := &sealedlog.Collector{Ring: ring, Boot: boot, Interval: *interval}
	tpm := sealedlog.TPMCounter{}
	if v, err := tpm.Increment(); err == nil {
		c.Counter = v
	}
	if pub, err := os.ReadFile(filepath.Join(*state, "reader.pub")); err == nil && len(pub) == 32 {
		if k, err := ecdh.X25519().NewPublicKey(pub); err == nil {
			c.Reader = k
			_ = publishPub(*state, *espDir, pub)
		}
	}
	c.OnClaim = func(uid uint32, pub []byte) bool {
		if err := publishPub(*state, *espDir, pub); err != nil {
			fmt.Fprintln(os.Stderr, "sealedlogd: claim:", err)
			return false
		}
		_ = writeAtomic(filepath.Join(*state, "owner"), []byte(strconv.FormatUint(uint64(uid), 10)+"\n"))
		return true
	}
	ingestFirmware(c)
	_ = c.Add(sealedlog.Record{Component: sealedlog.CompLogd, Code: sealedlog.CodeStart, Args: []uint64{b2u(fromLoader), b2u(c.Reader != nil)}})
	if perr != nil {
		fmt.Fprintln(os.Stderr, "sealedlogd: loader map:", perr)
		_ = c.Add(sealedlog.Record{Component: sealedlog.CompLogd, Code: sealedlog.CodeWarn, Args: []uint64{2}})
	}
	if efiErr != nil && !errors.Is(efiErr, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "sealedlogd: efivarfs:", efiErr)
		_ = c.Add(sealedlog.Record{Component: sealedlog.CompLogd, Code: sealedlog.CodeWarn, Args: []uint64{3}})
	}
	if breaks := ring.Check(entries); len(breaks) > 0 {
		_ = c.Add(sealedlog.Record{Component: sealedlog.CompLogd, Code: sealedlog.CodeWarn, Args: []uint64{1, uint64(len(breaks)), breaks[0].Seq}})
	}
	if err := cold.Migrate(entries, *keep); err != nil {
		_ = c.Add(sealedlog.Record{Component: sealedlog.CompLogd, Code: sealedlog.CodeFail, Args: []uint64{1}})
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	err = c.Serve(ctx, *socket)
	_ = c.Add(sealedlog.Record{Component: sealedlog.CompLogd, Code: sealedlog.CodeStop})
	if ferr := c.Flush(); err == nil {
		err = ferr
	}
	return err
}

func userKeyPath() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "sealedlog", "reader.key")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "sealedlog", "reader.key")
}

func claim(args []string) error {
	fs := flag.NewFlagSet("claim", flag.ContinueOnError)
	keyPath := fs.String("key", userKeyPath(), "where the reader private key lives")
	state := fs.String("state", defaultState, "collector state dir")
	socket := fs.String("socket", sealedlog.DefaultSocket, "collector socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var k *ecdh.PrivateKey
	if _, err := os.Stat(*keyPath); err == nil {
		if k, err = loadPriv(*keyPath); err != nil {
			return err
		}
	} else {
		nk, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(*keyPath), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(*keyPath, []byte(hex.EncodeToString(nk.Bytes())+"\n"), 0o600); err != nil {
			return err
		}
		k = nk
	}
	pubPath := filepath.Join(*state, "reader.pub")
	if cur, err := os.ReadFile(pubPath); err == nil {
		if bytes.Equal(cur, k.PublicKey().Bytes()) {
			return nil
		}
		return errors.New("the log already has another reader")
	}
	if err := sealedlog.Claim(*socket, k.PublicKey()); err != nil {
		return err
	}
	for i := 0; i < 50; i++ {
		if cur, err := os.ReadFile(pubPath); err == nil {
			if bytes.Equal(cur, k.PublicKey().Bytes()) {
				return nil
			}
			return errors.New("the log already has another reader")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("the collector did not adopt the key")
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// ingestFirmware seals what earlier stages left in EFI variables: the records
// of a kernel that could not reach the ring.
func ingestFirmware(c *sealedlog.Collector) {
	for _, name := range []string{sealedlog.VarEarlyPrev, sealedlog.VarEarly} {
		b, err := sealedlog.ReadEFIVar(name)
		if err != nil {
			continue
		}
		if early, err := sealedlog.ParseEarly(b); err == nil && len(early.Payload.Records) > 0 {
			if c.Seal(early.Boot, early.Payload) == nil {
				_ = sealedlog.DeleteEFIVar(name)
			}
		}
	}
	pstore, _ := filepath.Glob("/sys/fs/pstore/dmesg-*")
	if len(pstore) > 0 {
		_ = c.Add(sealedlog.Record{Component: sealedlog.CompKernelLinux, Code: sealedlog.KernelPanic, Args: []uint64{uint64(len(pstore))}})
		if b, err := os.ReadFile(pstore[len(pstore)-1]); err == nil {
			if len(b) > 1024 {
				b = b[len(b)-1024:]
			}
			_ = c.Add(sealedlog.Record{Component: sealedlog.CompKernelLinux, Code: sealedlog.CodeBlob,
				Args: []uint64{uint64(sealedlog.KernelPanic)}, Blob: b})
		}
	}
}

func emit(args []string) error {
	fs := flag.NewFlagSet("emit", flag.ContinueOnError)
	socket := fs.String("socket", sealedlog.DefaultSocket, "collector socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New("usage: emit COMPONENT EVENT [ARG...]")
	}
	comp, ok := sealedlog.ComponentByName(fs.Arg(0))
	if !ok {
		return fmt.Errorf("unknown component %q", fs.Arg(0))
	}
	code, ok := sealedlog.CodeByName(comp, fs.Arg(1))
	if !ok {
		return fmt.Errorf("unknown event %q for %s", fs.Arg(1), comp)
	}
	r := sealedlog.Record{Component: comp, Code: code}
	for _, a := range fs.Args()[2:] {
		v, err := strconv.ParseUint(a, 0, 64)
		if err != nil {
			return fmt.Errorf("argument %q is not a number", a)
		}
		r.Args = append(r.Args, v)
	}
	if len(r.Args) > sealedlog.MaxArgs {
		return fmt.Errorf("at most %d arguments", sealedlog.MaxArgs)
	}
	return sealedlog.Emit(*socket, r)
}

func loadPriv(path string) (*ecdh.PrivateKey, error) {
	var line string
	if path == "-" {
		s := bufio.NewScanner(os.Stdin)
		if s.Scan() {
			line = s.Text()
		}
	} else {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		line = string(b)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(line))
	if err != nil {
		return nil, errors.New("reader key is not hex")
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

func read(args []string) error {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	ringPath := fs.String("ring", filepath.Join(defaultState, "ring"), "ring file")
	coldDir := fs.String("cold", defaultCold, "archive")
	keyPath := fs.String("key", userKeyPath(), "reader private key in hex, - for stdin")
	boots := fs.Int("boots", 0, "only the newest N boots, 0 for all")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := loadPriv(*keyPath)
	if err != nil {
		return err
	}
	var entries []sealedlog.Entry
	if cold, err := (sealedlog.Cold{Dir: *coldDir}).ReadCold(); err == nil {
		entries = append(entries, cold...)
	}
	ring, f, err := sealedlog.ReadRingFile(*ringPath)
	switch {
	case err == nil:
		hot, err := ring.Scan()
		f.Close()
		if err != nil {
			return err
		}
		entries = merge(entries, hot)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	for _, b := range sealedlog.Verify(entries) {
		fmt.Printf("!! chain: seq %d: %s\n", b.Seq, b.Reason)
	}
	if v, err := (sealedlog.TPMCounter{}).Read(); err == nil && sealedlog.Rollback(entries, v) {
		fmt.Printf("!! the log is older than the TPM counter %d: it was replaced\n", v)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Header.Boot < entries[j].Header.Boot })
	keepFrom := uint32(0)
	if list := sealedlog.Boots(entries); *boots > 0 && len(list) > *boots {
		keepFrom = list[len(list)-*boots]
	}
	lastBoot := uint32(0)
	for _, e := range entries {
		if e.Header.Boot < keepFrom {
			continue
		}
		if e.Header.Boot != lastBoot {
			fmt.Printf("== boot %d\n", e.Header.Boot)
			lastBoot = e.Header.Boot
		}
		_, pt, err := sealedlog.Open(key, e.Raw)
		if err != nil {
			fmt.Printf("   seq %d: %v\n", e.Header.Seq, err)
			continue
		}
		p, err := sealedlog.DecodePayload(pt)
		if err != nil {
			fmt.Printf("   seq %d: %v\n", e.Header.Seq, err)
			continue
		}
		t := p.BaseUnixMs
		for _, r := range p.Records {
			t += r.DeltaMs
			when := "-"
			if p.BaseUnixMs != 0 {
				when = time.UnixMilli(int64(t)).UTC().Format("2006-01-02 15:04:05.000")
			}
			fmt.Printf("   %s %-12s %s%s\n", when, r.Component, sealedlog.CodeName(r.Component, r.Code), formatArgs(r))
		}
	}
	return nil
}

func formatArgs(r sealedlog.Record) string {
	var b strings.Builder
	for _, a := range r.Args {
		fmt.Fprintf(&b, " %d", a)
	}
	if r.Code == sealedlog.CodeBlob {
		for _, l := range strings.Split(strings.TrimRight(string(r.Blob), "\n"), "\n") {
			fmt.Fprintf(&b, "\n      | %s", l)
		}
	}
	return b.String()
}

func merge(a, b []sealedlog.Entry) []sealedlog.Entry {
	seen := map[uint64]bool{}
	for _, e := range a {
		seen[e.Header.Seq] = true
	}
	for _, e := range b {
		if !seen[e.Header.Seq] {
			a = append(a, e)
		}
	}
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j].Header.Seq < a[j-1].Header.Seq; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
	return a
}
