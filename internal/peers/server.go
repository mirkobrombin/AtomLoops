package peers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

type Limits struct {
	MaxConns        int
	PerAddress      int
	UploadRate      int
	BlocksPerMinute int
	ReleasesPerHour int
	StrikesToBan    int
	BanFor          time.Duration
	MaxBan          time.Duration
	Handshake       time.Duration
	Idle            time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxConns:        12,
		PerAddress:      2,
		UploadRate:      6 << 20,
		BlocksPerMinute: 24,
		ReleasesPerHour: 6,
		StrikesToBan:    3,
		BanFor:          time.Minute,
		MaxBan:          time.Hour,
		Handshake:       3 * time.Second,
		Idle:            15 * time.Second,
	}
}

type Release struct {
	ID        ID
	Version   string
	Bundle    Bundle
	Path      string
	BlockSize int
	Blocks    []string
}

func ReleaseOf(b Bundle, path string) (Release, error) {
	m, err := otad.ParseManifest(b.Manifest)
	if err != nil {
		return Release{}, err
	}
	size, blocks, err := m.RootFSBlockPlan()
	if err != nil {
		return Release{}, err
	}
	return Release{ID: sha256.Sum256(b.Manifest), Version: m.Version, Bundle: b, Path: path, BlockSize: size, Blocks: blocks}, nil
}

type visitor struct {
	conns       int
	strikes     int
	bans        int
	bannedUntil time.Time
	window      time.Time
	blocks      int
	hour        time.Time
	releases    int
}

type Server struct {
	Limits Limits
	Allow  func(net.Addr) bool
	Active func() bool
	Now    func() time.Time

	mu       sync.Mutex
	releases map[ID]*Release
	visitors map[string]*visitor
	conns    int
	bucket   *bucket
	served   int64
}

func NewServer(l Limits) *Server {
	return &Server{
		Limits:   l,
		Allow:    LocalNeighbour,
		Active:   func() bool { return true },
		Now:      time.Now,
		releases: map[ID]*Release{},
		visitors: map[string]*visitor{},
		bucket:   newBucket(l.UploadRate, otad.BlockSize),
	}
}

func (s *Server) Offer(r Release) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releases[r.ID] = &r
}

func (s *Server) Withdraw(id ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.releases, id)
}

func (s *Server) Served() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.served
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		host := hostOf(c.RemoteAddr())
		if !s.admit(c.RemoteAddr(), host) {
			c.Close()
			continue
		}
		go func() {
			defer s.leave(host)
			defer c.Close()
			s.session(c, host)
		}()
	}
}

func (s *Server) admit(addr net.Addr, host string) bool {
	if !s.Active() || (s.Allow != nil && !s.Allow(addr)) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.visitor(host)
	if s.Now().Before(v.bannedUntil) || v.conns >= s.Limits.PerAddress || s.conns >= s.Limits.MaxConns {
		return false
	}
	v.conns++
	s.conns++
	return true
}

func (s *Server) leave(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.visitors[host].conns--
	s.conns--
}

func (s *Server) visitor(host string) *visitor {
	v := s.visitors[host]
	if v == nil {
		v = &visitor{}
		s.visitors[host] = v
	}
	return v
}

func (s *Server) strike(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.visitor(host)
	v.strikes++
	if v.strikes < s.Limits.StrikesToBan {
		return
	}
	ban := s.Limits.BanFor << v.bans
	if ban <= 0 || ban > s.Limits.MaxBan {
		ban = s.Limits.MaxBan
	}
	v.bans++
	v.strikes = 0
	v.bannedUntil = s.Now().Add(ban)
}

func (s *Server) Banned(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.visitors[host]
	return v != nil && s.Now().Before(v.bannedUntil)
}

func (s *Server) quota(host string, release bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.visitor(host)
	now := s.Now()
	if release {
		if now.Sub(v.hour) >= time.Hour {
			v.hour, v.releases = now, 0
		}
		v.releases++
		return v.releases <= s.Limits.ReleasesPerHour
	}
	if now.Sub(v.window) >= time.Minute {
		v.window, v.blocks = now, 0
	}
	v.blocks++
	return v.blocks <= s.Limits.BlocksPerMinute
}

func (s *Server) latest() *Release {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best *Release
	for _, r := range s.releases {
		if best == nil || otad.Newer(r.Version, best.Version) {
			best = r
		}
	}
	return best
}

func (s *Server) release(id ID) *Release {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releases[id]
}

func (s *Server) session(c net.Conn, host string) {
	c.SetDeadline(s.Now().Add(s.Limits.Handshake))
	kind, p, err := readFrame(c, maxRequest)
	if err != nil {
		s.strike(host)
		return
	}
	id, ok := parseHello(p)
	if kind != msgHello || !ok {
		s.strike(host)
		return
	}
	if id == (ID{}) {
		r := s.latest()
		if r == nil || !s.quota(host, true) {
			writeFrame(c, msgRefuse, nil)
			return
		}
		writeFrame(c, msgRelease, r.Bundle.encode())
		return
	}
	r := s.release(id)
	if r == nil {
		s.strike(host)
		writeFrame(c, msgRefuse, nil)
		return
	}
	f, err := os.Open(r.Path)
	if err != nil {
		writeFrame(c, msgRefuse, nil)
		return
	}
	defer f.Close()
	if writeFrame(c, msgAccept, nil) != nil {
		return
	}
	buf := make([]byte, r.BlockSize)
	for {
		c.SetDeadline(s.Now().Add(s.Limits.Idle))
		kind, p, err := readFrame(c, maxRequest)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.strike(host)
			}
			return
		}
		if kind != msgBlock || len(p) != 4 {
			s.strike(host)
			return
		}
		i := int(binary.BigEndian.Uint32(p))
		if i >= len(r.Blocks) {
			s.strike(host)
			return
		}
		if !s.Active() || !s.quota(host, false) {
			writeFrame(c, msgRefuse, nil)
			return
		}
		n, err := f.ReadAt(buf, int64(i)*int64(r.BlockSize))
		if err != nil && !errors.Is(err, io.EOF) {
			writeFrame(c, msgRefuse, nil)
			return
		}
		sum := sha256.Sum256(buf[:n])
		if hex.EncodeToString(sum[:]) != r.Blocks[i] {
			s.Withdraw(r.ID)
			writeFrame(c, msgRefuse, nil)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.Limits.Idle)
		err = s.bucket.wait(ctx, n)
		cancel()
		if err != nil {
			return
		}
		c.SetDeadline(s.Now().Add(s.Limits.Idle))
		if writeFrame(c, msgData, append(binary.BigEndian.AppendUint32(nil, uint32(i)), buf[:n]...)) != nil {
			return
		}
		s.mu.Lock()
		s.served += int64(n)
		s.mu.Unlock()
	}
}

func hostOf(a net.Addr) string {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP.String()
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

func LocalNeighbour(a net.Addr) bool {
	t, ok := a.(*net.TCPAddr)
	if !ok || t.IP.IsLoopback() || !(t.IP.IsPrivate() || t.IP.IsLinkLocalUnicast()) {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.Contains(t.IP) && !n.IP.IsLoopback() {
			return true
		}
	}
	return false
}

type bucket struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	have  float64
	last  time.Time
}

func newBucket(rate, burst int) *bucket {
	return &bucket{rate: float64(rate), burst: float64(burst), have: float64(burst), last: time.Now()}
}

func (b *bucket) wait(ctx context.Context, n int) error {
	if b.rate <= 0 {
		return nil
	}
	for {
		b.mu.Lock()
		now := time.Now()
		b.have = min(b.burst, b.have+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
		if b.have >= float64(n) || (b.have >= b.burst && float64(n) > b.burst) {
			b.have -= float64(n)
			b.mu.Unlock()
			return nil
		}
		need := time.Duration((min(float64(n), b.burst) - b.have) / b.rate * float64(time.Second))
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(need):
		}
	}
}
