package peers

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	askMagic  = "SINTY-WHO-1"
	haveMagic = "SINTY-HAVE-1"
	askSize   = 64
)

var Group = &net.UDPAddr{IP: net.IPv4(239, 255, 77, 13), Port: 7714}

func askPacket(id ID) []byte {
	p := make([]byte, askSize)
	copy(p, askMagic)
	copy(p[len(askMagic):], id[:])
	return p
}

func parseAsk(p []byte) (ID, bool) {
	var id ID
	if len(p) != askSize || string(p[:len(askMagic)]) != askMagic {
		return id, false
	}
	copy(id[:], p[len(askMagic):])
	return id, true
}

func havePacket(id ID, port int) []byte {
	p := append([]byte(haveMagic), id[:]...)
	return binary.BigEndian.AppendUint16(p, uint16(port))
}

func parseHave(p []byte) (ID, int, bool) {
	var id ID
	if len(p) != len(haveMagic)+len(id)+2 || string(p[:len(haveMagic)]) != haveMagic {
		return id, 0, false
	}
	copy(id[:], p[len(haveMagic):])
	return id, int(binary.BigEndian.Uint16(p[len(haveMagic)+len(id):])), true
}

type Responder struct {
	Server   *Server
	Port     int
	Allow    func(net.IP) bool
	PerAsker time.Duration
	PerSec   int
	Now      func() time.Time

	mu     sync.Mutex
	last   map[string]time.Time
	second time.Time
	count  int
}

func NewResponder(s *Server, port int) *Responder {
	return &Responder{Server: s, Port: port, Allow: localIP, PerAsker: 10 * time.Second, PerSec: 10, Now: time.Now, last: map[string]time.Time{}}
}

func (r *Responder) answer(p []byte, from net.IP) []byte {
	id, ok := parseAsk(p)
	if !ok || (r.Allow != nil && !r.Allow(from)) || !r.Server.Active() {
		return nil
	}
	if id == (ID{}) {
		latest := r.Server.latest()
		if latest == nil {
			return nil
		}
		id = latest.ID
	} else if r.Server.release(id) == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.Now()
	key := from.String()
	if t, ok := r.last[key]; ok && now.Sub(t) < r.PerAsker {
		return nil
	}
	if now.Sub(r.second) >= time.Second {
		r.second, r.count = now, 0
	}
	if r.count >= r.PerSec {
		return nil
	}
	r.count++
	r.last[key] = now
	if len(r.last) > 4096 {
		for k, t := range r.last {
			if now.Sub(t) >= r.PerAsker {
				delete(r.last, k)
			}
		}
	}
	return havePacket(id, r.Port)
}

func (r *Responder) Serve(conn net.PacketConn) error {
	buf := make([]byte, 512)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		u, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		if reply := r.answer(buf[:n], u.IP); reply != nil {
			conn.WriteTo(reply, from)
		}
	}
}

func ListenGroup() (*net.UDPConn, error) {
	return net.ListenMulticastUDP("udp4", nil, Group)
}

func Find(ctx context.Context, conn net.PacketConn, to net.Addr, id ID, wait time.Duration) ([]string, ID, error) {
	select {
	case <-time.After(time.Duration(rand.Int64N(int64(500 * time.Millisecond)))):
	case <-ctx.Done():
		return nil, id, ctx.Err()
	}
	if _, err := conn.WriteTo(askPacket(id), to); err != nil {
		return nil, id, err
	}
	deadline := time.Now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetReadDeadline(deadline)
	seen := map[string]bool{}
	var out []string
	want := id
	buf := make([]byte, 512)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return out, want, nil
			}
			return out, want, err
		}
		got, port, ok := parseHave(buf[:n])
		u, isUDP := from.(*net.UDPAddr)
		if !ok || !isUDP || port == 0 {
			continue
		}
		if want == (ID{}) {
			want = got
		}
		if got != want {
			continue
		}
		addr := net.JoinHostPort(u.IP.String(), strconv.Itoa(port))
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
		if len(out) >= 8 {
			return out, want, nil
		}
	}
}

func localIP(ip net.IP) bool {
	return LocalNeighbour(&net.TCPAddr{IP: ip})
}
