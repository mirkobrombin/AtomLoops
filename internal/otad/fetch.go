package otad

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	return httpx.New(&http.Client{}).
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

// FetchTo downloads url to dest atomically (temp + fsync + rename). Transport
// failures, server errors (408, 429, 5xx) and connections cut mid-body are
// retried with backoff, resuming from the bytes already on disk with a Range
// request. A download is abandoned only when no data arrives for stallTimeout,
// never because the whole transfer takes long. Returns the bytes written.
func FetchTo(ctx context.Context, url, dest string) (int64, error) {
	tmp := dest + ".tmp"
	os.Remove(tmp)
	var last error
	for attempt := 0; attempt < fetchAttempts; attempt++ {
		if attempt > 0 {
			wait := retryDelay << (attempt - 1)
			if wait > maxRetryDelay {
				wait = maxRetryDelay
			}
			select {
			case <-ctx.Done():
				os.Remove(tmp)
				return 0, ctx.Err()
			case <-time.After(wait):
			}
		}
		n, retry, err := fetchOnce(ctx, url, tmp)
		if err == nil {
			if err := os.Rename(tmp, dest); err != nil {
				os.Remove(tmp)
				return 0, err
			}
			if err := syncDir(filepath.Dir(dest)); err != nil {
				return 0, err
			}
			return n, nil
		}
		last = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	os.Remove(tmp)
	return 0, last
}

var (
	fetchAttempts = 6
	retryDelay    = time.Second
	maxRetryDelay = 30 * time.Second
	stallTimeout  = 60 * time.Second
)

type stallReader struct {
	r     io.Reader
	timer *time.Timer
}

func (s *stallReader) Read(b []byte) (int, error) {
	n, err := s.r.Read(b)
	if n > 0 {
		s.timer.Reset(stallTimeout)
	}
	return n, err
}

func retryable(code int) bool {
	return code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500
}

func fetchOnce(parent context.Context, url, tmp string) (int64, bool, error) {
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()
	have, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, false, err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	timer := time.AfterFunc(stallTimeout, cancel)
	defer timer.Stop()
	if have > 0 {
		ctx = context.WithValue(ctx, rangeKey{}, have)
	}
	resp, err := get(ctx, url)
	if err != nil {
		return 0, parent.Err() == nil && !errors.Is(err, errRedirect), err
	}
	defer resp.Body.Close()
	total := resp.ContentLength
	switch {
	case resp.StatusCode == http.StatusPartialContent && have > 0:
		var start, end, size int64
		if _, err := fmt.Sscanf(resp.Header.Get("Content-Range"), "bytes %d-%d/%d", &start, &end, &size); err != nil || start != have {
			f.Truncate(0)
			return 0, true, fmt.Errorf("fetch %s: unusable resume range %q", url, resp.Header.Get("Content-Range"))
		}
		total = size
	case resp.StatusCode == http.StatusOK:
		if err := f.Truncate(0); err != nil {
			return 0, false, err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return 0, false, err
		}
		have = 0
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		f.Truncate(0)
		return 0, true, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	default:
		return 0, retryable(resp.StatusCode), fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	var body io.Reader = &stallReader{r: resp.Body, timer: timer}
	if cb, ok := parent.Value(progressKey{}).(ProgressFunc); ok && cb != nil {
		body = &progressReader{r: body, cb: cb, done: have, total: total}
	}
	n, err := io.Copy(f, body)
	if err != nil {
		if parent.Err() != nil {
			return 0, false, err
		}
		return 0, true, fmt.Errorf("fetch %s: %w", url, err)
	}
	if total >= 0 && have+n != total {
		return 0, true, fmt.Errorf("fetch %s: got %d of %d bytes", url, have+n, total)
	}
	if err := f.Sync(); err != nil {
		return 0, false, err
	}
	return have + n, false, nil
}

type rangeKey struct{}

const maxRedirects = 5

var errRedirect = errors.New("unusable redirect")

func get(ctx context.Context, rawURL string) (*http.Response, error) {
	for hop := 0; ; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		if from, ok := ctx.Value(rangeKey{}).(int64); ok && from > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", from))
		}
		resp, err := fetchClient().Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", rawURL, err)
		}
		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
			http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			return resp, nil
		}
		loc, err := resp.Location()
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w: no location", rawURL, errRedirect)
		}
		if hop >= maxRedirects {
			return nil, fmt.Errorf("fetch %s: %w: too many redirects", rawURL, errRedirect)
		}
		if req.URL.Scheme == "https" && loc.Scheme != "https" {
			return nil, fmt.Errorf("fetch %s: %w: refusing redirect to %s", rawURL, errRedirect, loc.Scheme)
		}
		rawURL = loc.String()
	}
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
