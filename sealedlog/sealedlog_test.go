package sealedlog

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/internal/sealedlog"
)

func setup(t *testing.T) (string, string, *net.UnixConn) {
	t.Helper()
	dir := t.TempDir()
	dict := filepath.Join(dir, "components")
	if err := os.WriteFile(dict, []byte("13 sinty-nm -\n11 shell session user\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "socket")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return dict, sock, conn
}

func receive(t *testing.T, conn *net.UnixConn) sealedlog.Record {
	t.Helper()
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	p, err := sealedlog.DecodePayload(append([]byte{0}, buf[:n]...))
	if err != nil || len(p.Records) != 1 {
		t.Fatalf("decoded %v %v", p, err)
	}
	return p.Records[0]
}

func TestLogSharedAndFamilyEvents(t *testing.T) {
	dict, sock, conn := setup(t)
	nm, err := OpenAt("sinty-nm", dict, sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := nm.Log("ready", 7); err != nil {
		t.Fatal(err)
	}
	r := receive(t, conn)
	if r.Component != 13 || r.Code != sealedlog.CodeReady || len(r.Args) != 1 || r.Args[0] != 7 {
		t.Fatalf("got %+v", r)
	}
	shell, err := OpenAt("shell", dict, sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := shell.Log("first-frame", 1, 2, 3, 4); err != nil {
		t.Fatal(err)
	}
	r = receive(t, conn)
	if r.Component != 11 || r.Code != sealedlog.SessionFirstFrame || len(r.Args) != 3 {
		t.Fatalf("got %+v", r)
	}
}

func TestRejectsUnknownNames(t *testing.T) {
	dict, sock, _ := setup(t)
	if _, err := OpenAt("nobody", dict, sock); !errors.Is(err, ErrUnknownComponent) {
		t.Fatalf("got %v", err)
	}
	nm, err := OpenAt("sinty-nm", dict, sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := nm.Log("first-frame"); !errors.Is(err, ErrUnknownEvent) {
		t.Fatalf("a component without the session family logged a session event: %v", err)
	}
}

func TestNilWriterAndMissingCollector(t *testing.T) {
	var w *Writer
	if err := w.Log("ready"); err != nil {
		t.Fatal(err)
	}
	dict, _, _ := setup(t)
	nm, err := OpenAt("sinty-nm", dict, filepath.Join(t.TempDir(), "none"))
	if err != nil {
		t.Fatal(err)
	}
	if err := nm.Log("ready"); err == nil {
		t.Fatal("logging without a collector reported success")
	}
}
