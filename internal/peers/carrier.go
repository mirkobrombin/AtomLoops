package peers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mirkobrombin/atomloops/internal/otad"
)

var ErrNoNeighbours = errors.New("peers: no neighbour has this release")

type Carrier struct {
	Server   *Server
	Fetcher  Fetcher
	Discover func(ctx context.Context, id ID) ([]string, error)
	Range    func(ctx context.Context, url string, offset int64, length int) ([]byte, error)
	Every    time.Duration
	Allowed  func() bool

	mu   sync.Mutex
	last time.Time
}

func (c *Carrier) Offer(r otad.CarriedRelease) {
	rel, err := ReleaseOf(Bundle{Manifest: r.Data, Sig: r.Sig, Cert: r.Cert, CertSig: r.CertSig}, r.Path)
	if err != nil {
		return
	}
	c.Server.Offer(rel)
}

func (c *Carrier) FetchRootFS(ctx context.Context, r otad.CarriedRelease, dest string) error {
	if c.Allowed != nil && !c.Allowed() {
		return ErrNoNeighbours
	}
	plan, err := PlanOf(r.Data)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.Every > 0 && time.Since(c.last) < c.Every {
		c.mu.Unlock()
		return ErrNoNeighbours
	}
	c.last = time.Now()
	c.mu.Unlock()
	addrs, err := c.Discover(ctx, plan.ID)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return ErrNoNeighbours
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	fetcher := c.Fetcher
	url := r.Manifest.RootFSURL
	fetcher.Fallback = func(ctx context.Context, offset int64, length int) ([]byte, error) {
		return c.Range(ctx, url, offset, length)
	}
	res, err := fetcher.Fetch(ctx, plan, addrs, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	log.Printf("peers: %s carried, %d blocks from neighbours, %d from the server, dropped %v", r.Manifest.Version, res.FromPeers, res.FromServer, res.Dropped)
	return nil
}

func MulticastDiscover(wait time.Duration) func(ctx context.Context, id ID) ([]string, error) {
	return func(ctx context.Context, id ID) ([]string, error) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		addrs, _, err := Find(ctx, conn, Group, id, wait)
		return addrs, err
	}
}

func NewCarrier(s *Server) *Carrier {
	return &Carrier{
		Server:   s,
		Fetcher:  Fetcher{Parallel: 4, MaxPeers: 3, BlockTimeout: 20 * time.Second},
		Discover: MulticastDiscover(1500 * time.Millisecond),
		Range:    otad.FetchRange,
		Every:    time.Minute,
	}
}

func (c *Carrier) Run(ctx context.Context, port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	group, err := ListenGroup()
	if err != nil {
		ln.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		group.Close()
	}()
	go NewResponder(c.Server, port).Serve(group)
	return c.Server.Serve(ln)
}
