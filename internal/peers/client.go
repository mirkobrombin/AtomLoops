package peers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
	"github.com/mirkobrombin/atomloops/internal/trust"
)

var (
	ErrNoSource    = errors.New("peers: no neighbour and no server for a block")
	ErrServerBlock = errors.New("peers: the server sent a block that does not match the release")
	ErrStale       = errors.New("peers: the neighbour's release is not newer than the installed one")
)

type Plan struct {
	ID        ID
	BlockSize int
	Blocks    []string
}

func PlanOf(manifest []byte) (Plan, error) {
	m, err := otad.ParseManifest(manifest)
	if err != nil {
		return Plan{}, err
	}
	size, blocks, err := m.RootFSBlockPlan()
	if err != nil {
		return Plan{}, err
	}
	return Plan{ID: sha256.Sum256(manifest), BlockSize: size, Blocks: blocks}, nil
}

type Fetcher struct {
	Dial         func(ctx context.Context, addr string) (net.Conn, error)
	Parallel     int
	MaxPeers     int
	BlockTimeout time.Duration
	Fallback     func(ctx context.Context, offset int64, length int) ([]byte, error)
}

type Result struct {
	FromPeers  int
	FromServer int
	Dropped    []string
}

type neighbour struct {
	addr string
	mu   sync.Mutex
	conn net.Conn
	bad  bool
	slow int
}

func (f *Fetcher) dial(ctx context.Context, addr string) (net.Conn, error) {
	if f.Dial != nil {
		return f.Dial(ctx, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func (f *Fetcher) Fetch(ctx context.Context, plan Plan, addrs []string, dest *os.File) (Result, error) {
	parallel := max(f.Parallel, 1)
	limit := f.MaxPeers
	if limit <= 0 {
		limit = 3
	}
	timeout := f.BlockTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	shuffled := append([]string(nil), addrs...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	if len(shuffled) > limit {
		shuffled = shuffled[:limit]
	}
	var ns []*neighbour
	for _, a := range shuffled {
		ns = append(ns, &neighbour{addr: a})
	}
	defer func() {
		for _, n := range ns {
			if n.conn != nil {
				n.conn.Close()
			}
		}
	}()

	var mu sync.Mutex
	var res Result
	drop := func(n *neighbour) {
		n.bad = true
		if n.conn != nil {
			n.conn.Close()
			n.conn = nil
		}
		mu.Lock()
		res.Dropped = append(res.Dropped, n.addr)
		mu.Unlock()
	}

	jobs := make(chan int)
	errs := make(chan error, parallel)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for w := range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				data, fromPeer, err := f.block(ctx, plan, i, ns, w, timeout, drop)
				if err == nil {
					_, err = dest.WriteAt(data, int64(i)*int64(plan.BlockSize))
				}
				if err != nil {
					errs <- err
					cancel()
					return
				}
				mu.Lock()
				if fromPeer {
					res.FromPeers++
				} else {
					res.FromServer++
				}
				mu.Unlock()
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i := range plan.Blocks {
			select {
			case jobs <- i:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()
	select {
	case err := <-errs:
		return res, err
	default:
	}
	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return res, err
	}
	return res, nil
}

func (f *Fetcher) block(ctx context.Context, plan Plan, i int, ns []*neighbour, worker int, timeout time.Duration, drop func(*neighbour)) ([]byte, bool, error) {
	try := func(n *neighbour) ([]byte, bool) {
		defer n.mu.Unlock()
		if n.bad {
			return nil, false
		}
		data, err := f.ask(ctx, n, plan, i, timeout)
		switch {
		case err == nil && matches(data, plan.Blocks[i]):
			return data, true
		case err == nil:
			drop(n)
		default:
			if n.conn != nil {
				n.conn.Close()
				n.conn = nil
			}
			n.slow++
			if n.slow >= 2 || errors.Is(err, errRefused) {
				drop(n)
			}
		}
		return nil, false
	}
	var busy []*neighbour
	for k := range ns {
		n := ns[(worker+i+k)%len(ns)]
		if !n.mu.TryLock() {
			busy = append(busy, n)
			continue
		}
		if data, ok := try(n); ok {
			return data, true, nil
		}
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
	}
	for _, n := range busy {
		n.mu.Lock()
		if data, ok := try(n); ok {
			return data, true, nil
		}
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
	}
	if f.Fallback == nil {
		return nil, false, fmt.Errorf("%w %d", ErrNoSource, i)
	}
	data, err := f.Fallback(ctx, int64(i)*int64(plan.BlockSize), plan.BlockSize)
	if err != nil {
		return nil, false, err
	}
	if !matches(data, plan.Blocks[i]) {
		return nil, false, fmt.Errorf("%w (block %d)", ErrServerBlock, i)
	}
	return data, false, nil
}

func (f *Fetcher) ask(ctx context.Context, n *neighbour, plan Plan, i int, timeout time.Duration) ([]byte, error) {
	if n.conn == nil {
		dctx, cancel := context.WithTimeout(ctx, timeout)
		c, err := f.dial(dctx, n.addr)
		cancel()
		if err != nil {
			return nil, err
		}
		c.SetDeadline(time.Now().Add(timeout))
		if err := writeFrame(c, msgHello, helloPayload(plan.ID)); err != nil {
			c.Close()
			return nil, err
		}
		kind, _, err := readFrame(c, maxRequest)
		if err != nil {
			c.Close()
			return nil, err
		}
		if kind != msgAccept {
			c.Close()
			return nil, errRefused
		}
		n.conn = c
	}
	c := n.conn
	c.SetDeadline(time.Now().Add(timeout))
	if err := writeFrame(c, msgBlock, binary.BigEndian.AppendUint32(nil, uint32(i))); err != nil {
		return nil, err
	}
	kind, p, err := readFrame(c, plan.BlockSize+4)
	if err != nil {
		return nil, err
	}
	if kind == msgRefuse {
		return nil, errRefused
	}
	if kind != msgData || len(p) < 4 || int(binary.BigEndian.Uint32(p)) != i {
		return nil, errFrame
	}
	return p[4:], nil
}

func matches(data []byte, want string) bool {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == want
}

func AskRelease(ctx context.Context, dial func(ctx context.Context, addr string) (net.Conn, error), addr string) (Bundle, error) {
	if dial == nil {
		var d net.Dialer
		dial = func(ctx context.Context, a string) (net.Conn, error) { return d.DialContext(ctx, "tcp", a) }
	}
	c, err := dial(ctx, addr)
	if err != nil {
		return Bundle{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	} else {
		c.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if err := writeFrame(c, msgHello, helloPayload(ID{})); err != nil {
		return Bundle{}, err
	}
	kind, p, err := readFrame(c, maxRelease)
	if err != nil {
		return Bundle{}, err
	}
	if kind != msgRelease {
		return Bundle{}, errRefused
	}
	return decodeBundle(p)
}

func VerifyRelease(b Bundle, rootPub []byte, installed string, now time.Time) (otad.Manifest, error) {
	signing, _, err := trust.VerifyCert(b.Cert, b.CertSig, rootPub, now)
	if err != nil {
		return otad.Manifest{}, err
	}
	if !trust.Verify(b.Manifest, b.Sig, signing) {
		return otad.Manifest{}, errors.New("peers: the neighbour's manifest signature is invalid")
	}
	m, err := otad.ParseManifest(b.Manifest)
	if err != nil {
		return otad.Manifest{}, err
	}
	if m.ExpiredAt(now) {
		return otad.Manifest{}, fmt.Errorf("peers: the neighbour's manifest for %s has expired", m.Version)
	}
	if !otad.Newer(m.Version, installed) {
		return otad.Manifest{}, ErrStale
	}
	if _, _, err := m.RootFSBlockPlan(); err != nil {
		return otad.Manifest{}, err
	}
	return m, nil
}
