package sealedlog

import (
	"context"
	"crypto/ecdh"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Collector gathers the records of the running boot and seals them into the
// ring a block at a time. A block is written when it is full, when a record
// is critical, on every Interval and on Close, so a hard power cut loses at
// most one interval of routine events and never a failure.
type Collector struct {
	Ring     *Ring
	Reader   *ecdh.PublicKey
	Boot     uint32
	Counter  uint64
	Interval time.Duration
	Now      func() time.Time

	// OnClaim, when set, receives a reader public key sent by a desktop user
	// while the collector has none, and returns whether it was adopted.
	OnClaim func(uid uint32, pub []byte) bool

	mu      sync.Mutex
	pending Payload
	size    int
	last    time.Time
	held    [][]byte
}

// MaxHeld bounds the blocks kept in memory while no reader key exists.
const MaxHeld = 64

// SetReader adopts the reader key and seals everything held so far.
func (c *Collector) SetReader(k *ecdh.PublicKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Reader = k
	held := c.held
	c.held = nil
	for _, p := range held {
		if _, err := c.Ring.Append(c.Reader, c.Boot, c.Counter, p); err != nil {
			return err
		}
	}
	return c.flushLocked()
}

// Critical reports whether a record must reach the disk at once.
func Critical(r Record) bool {
	switch r.Code {
	case CodeFail, CodeCrash, CodeTimeout, CodeDenied, CodeBlob:
		return true
	}
	switch FamilyOf(r.Component) {
	case FamilyKernel:
		return r.Code == KernelPanic || r.Code == KernelOops || r.Code == KernelWatchdog ||
			r.Code == KernelInitExit || r.Code == KernelDriverFail
	case FamilyOTA:
		return r.Code == OtaRollback || r.Code == OtaReboot || r.Code == OtaVerifyFail
	case FamilySession:
		return r.Code == SessionLoginFail || r.Code == SessionAppCrash || r.Code == SessionDiskError ||
			r.Code == SessionBatteryCritical
	case FamilyInit:
		return r.Code == InitUnitFail || r.Code == InitShutdown
	}
	return false
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Add records r, stamping its time.
func (c *Collector) Add(r Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.now()
	if len(c.pending.Records) == 0 {
		c.pending.BaseUnixMs = uint64(t.UnixMilli())
		c.size = len(Payload{BaseUnixMs: c.pending.BaseUnixMs}.Encode())
		r.DeltaMs = 0
	} else {
		r.DeltaMs = uint64(t.Sub(c.last).Milliseconds())
	}
	n := len(AppendRecord(nil, r))
	if n > MaxPayload-c.size {
		if len(c.pending.Records) == 0 {
			return ErrTooLarge
		}
		if err := c.flushLocked(); err != nil {
			return err
		}
		c.mu.Unlock()
		err := c.Add(r)
		c.mu.Lock()
		return err
	}
	c.pending.Records = append(c.pending.Records, r)
	c.size += n
	c.last = t
	if Critical(r) {
		return c.flushLocked()
	}
	return nil
}

// Flush writes the pending records, if any.
func (c *Collector) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.flushLocked()
}

func (c *Collector) flushLocked() error {
	if len(c.pending.Records) == 0 {
		return nil
	}
	if c.Reader == nil {
		if len(c.held) < MaxHeld {
			c.held = append(c.held, c.pending.Encode())
		}
		c.pending = Payload{}
		c.size = 0
		return nil
	}
	if _, err := c.Ring.Append(c.Reader, c.Boot, c.Counter, c.pending.Encode()); err != nil {
		return err
	}
	c.pending = Payload{}
	c.size = 0
	return nil
}

// Seal writes a payload that already carries its own times, such as records a
// kernel left in firmware memory, as one block of the given boot.
func (c *Collector) Seal(boot uint32, p Payload) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Reader == nil {
		if len(c.held) >= MaxHeld {
			return ErrTooLarge
		}
		c.held = append(c.held, p.Encode())
		return nil
	}
	_, err := c.Ring.Append(c.Reader, boot, c.Counter, p.Encode())
	return err
}

// Allowed is the socket policy: system users log as anything, a desktop user
// only as the components the dictionary marks for users.
func Allowed(uid uint32, comp Component) bool {
	if uid < 1000 {
		return true
	}
	return UserComponent(comp)
}

// Serve receives records on a unix datagram socket until ctx ends. Each
// datagram holds one or more records encoded with AppendRecord; their time
// deltas are ignored and replaced by the time of arrival.
func (c *Collector) Serve(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_ = os.Remove(path)
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := os.Chmod(path, 0o666); err != nil {
		return err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = passCredentials(int(fd))
	}); err != nil {
		return err
	}
	if serr != nil {
		return serr
	}
	interval := c.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				conn.Close()
				return
			case <-t.C:
				_ = c.Flush()
			}
		}
	}()
	buf := make([]byte, MaxPayload)
	oob := make([]byte, credSpace)
	for {
		n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
		if err != nil {
			if ctx.Err() != nil {
				return c.Flush()
			}
			if errors.Is(err, net.ErrClosed) {
				return c.Flush()
			}
			continue
		}
		uid, ok := senderUID(oob[:oobn])
		if !ok {
			continue
		}
		if n == 2+32 && buf[0] == claimTag[0] && buf[1] == claimTag[1] {
			c.claim(uid, buf[2:n])
			continue
		}
		p, err := DecodePayload(append([]byte{0}, buf[:n]...))
		if err != nil {
			continue
		}
		for _, r := range p.Records {
			if !Allowed(uid, r.Component) {
				_ = c.Add(Record{Component: CompLogd, Code: CodeDenied, Args: []uint64{uint64(uid), uint64(r.Component)}})
				continue
			}
			_ = c.Add(r)
		}
	}
}

var claimTag = [2]byte{0xff, 'C'}

func (c *Collector) claim(uid uint32, pub []byte) {
	c.mu.Lock()
	has := c.Reader != nil
	c.mu.Unlock()
	if has || uid < 1000 || c.OnClaim == nil {
		_ = c.Add(Record{Component: CompLogd, Code: CodeDenied, Args: []uint64{uint64(uid), 0}})
		return
	}
	k, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil || !c.OnClaim(uid, pub) {
		return
	}
	if c.SetReader(k) == nil {
		_ = c.Add(Record{Component: CompLogd, Code: CodeReady, Args: []uint64{uint64(uid)}})
	}
}

// Claim offers a reader public key to the collector at path. Only the first
// desktop user to claim, while no key exists, becomes the reader.
func Claim(path string, pub *ecdh.PublicKey) error {
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(append(claimTag[:], pub.Bytes()...))
	return err
}

// DefaultSocket is where the collector listens.
const DefaultSocket = "/run/sealedlog/socket"

// Emit sends records to the collector at path.
func Emit(path string, records ...Record) error {
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	var b []byte
	for _, r := range records {
		r.DeltaMs = 0
		b = AppendRecord(b, r)
	}
	_, err = conn.Write(b)
	return err
}
