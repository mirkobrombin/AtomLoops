package otad

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/mirkobrombin/go-foundation/pkg/httpx"
	"github.com/mirkobrombin/go-foundation/pkg/resiliency"
)

// fetchClient is the retrying HTTP client for pulling manifests and artifacts.
// go-foundation's httpx wraps net/http with retry (transport errors) + an optional
// circuit breaker, so a flaky mirror does not abort an update. This is the
// service tier: unlike a minimal, zero-dependency PID 1, the OTA daemon is a
// network service and leans on go-foundation for exactly this.
func fetchClient() *httpx.Client {
	return httpx.New(&http.Client{Timeout: 60 * time.Second}).
		WithRetry(func(o *resiliency.RetryOptions) {
			o.Attempts = 4
			o.InitialDelay = 20 * time.Millisecond
		})
}

// ProgressFunc reports download progress as bytes flow: done so far and the total
// (total is -1 when the server does not send Content-Length).
type ProgressFunc func(done, total int64)

type progressKey struct{}

// WithProgress attaches a callback FetchTo invokes during an artifact download, so the
// update agent can drive the dock progress bar. Opt-in: no callback, no overhead.
func WithProgress(ctx context.Context, cb ProgressFunc) context.Context {
	return context.WithValue(ctx, progressKey{}, cb)
}

type progressReader struct {
	r     io.Reader
	cb    ProgressFunc
	done  int64
	total int64
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.done += int64(n)
		p.cb(p.done, p.total)
	}
	return n, err
}

// FetchTo downloads url to dest atomically (temp + fsync + rename), retrying
// transient transport failures. Returns the number of bytes written.
func FetchTo(ctx context.Context, url, dest string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := fetchClient().Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	var body io.Reader = resp.Body
	if cb, ok := ctx.Value(progressKey{}).(ProgressFunc); ok && cb != nil {
		body = &progressReader{r: resp.Body, cb: cb, total: resp.ContentLength}
	}
	n, err := io.Copy(f, body)
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return 0, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return 0, err
	}
	f.Close()
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	return n, nil
}

// VerifyManifestSig verifies a detached Ed25519 signature (sig) over data against
// pubkey. This is the Atom Loops manifest trust check (A4.1): a raw detached
// file signature, deliberately NOT go-foundation's auth package, which does
// JWT-like tokens (a different layer, for device/server auth).
func VerifyManifestSig(data, sig, pubkey []byte) bool {
	if len(pubkey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubkey), data, sig)
}
