package otad

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func withFreeSpace(t *testing.T, free int64) {
	t.Helper()
	old := freeSpace
	freeSpace = func(string) (int64, error) { return free, nil }
	t.Cleanup(func() { freeSpace = old })
}

func TestFetchToRefusesReleaseThatDoesNotFit(t *testing.T) {
	body := bytes.Repeat([]byte("r"), 1<<20)
	var sent atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		n, _ := w.Write(body)
		sent.Add(int64(n))
	}))
	defer srv.Close()
	withFreeSpace(t, 4096)

	dest := filepath.Join(t.TempDir(), "rootfs-next.erofs")
	_, err := FetchTo(context.Background(), srv.URL, dest)
	if !errors.Is(err, ErrNoSpace) {
		t.Fatalf("err = %v, want ErrNoSpace", err)
	}
	if info, err := os.Stat(dest + ".tmp"); err == nil && info.Size() > 0 {
		t.Fatalf("%d bytes written before refusing", info.Size())
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("destination created")
	}
}

func TestFetchToCountsTheResumedPartAsAlreadyStored(t *testing.T) {
	body := bytes.Repeat([]byte("p"), 64<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "rootfs", time.Time{}, bytes.NewReader(body))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "rootfs-next.erofs")
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, body[:60<<10], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := recordPartial(tmp, srv.URL, `"v1"`); err != nil {
		t.Fatal(err)
	}
	withFreeSpace(t, 8<<10)

	if _, err := FetchTo(context.Background(), srv.URL, dest); err != nil {
		t.Fatalf("resume with room for the rest: %v", err)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, body) {
		t.Fatalf("resumed file differs")
	}
}

func TestFetchToKeepsPartialWhenSpaceRunsShort(t *testing.T) {
	body := bytes.Repeat([]byte("k"), 64<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "rootfs", time.Time{}, bytes.NewReader(body))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "rootfs-next.erofs")
	tmp := dest + ".tmp"
	os.WriteFile(tmp, body[:16<<10], 0o644)
	recordPartial(tmp, srv.URL, `"v1"`)
	withFreeSpace(t, 1<<10)

	if _, err := FetchTo(context.Background(), srv.URL, dest); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("err = %v, want ErrNoSpace", err)
	}
	if info, err := os.Stat(tmp); err != nil || info.Size() != 16<<10 {
		t.Fatalf("partial download not kept for a later resume: %v", err)
	}
}

func TestEnsureSpaceNamesWhatIsMissing(t *testing.T) {
	withFreeSpace(t, 1<<30)
	dest := filepath.Join(t.TempDir(), "rootfs-next.erofs")
	err := ensureSpace(dest, 400*(4<<20))
	if !errors.Is(err, ErrNoSpace) {
		t.Fatalf("err = %v, want ErrNoSpace", err)
	}
	if want := "needs 1.6 GB, 1.0 GB free"; !strings.Contains(err.Error(), want) {
		t.Fatalf("message %q does not say %q", err, want)
	}
	if err := ensureSpace(dest, 1<<29); err != nil {
		t.Fatalf("release that fits refused: %v", err)
	}
}
