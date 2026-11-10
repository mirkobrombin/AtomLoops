package otad

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/internal/deployment"
)

func promotedMachine(t *testing.T) (string, StageDirs, []byte) {
	t.Helper()
	base, rootPub := signedFeedV2(t, "verity-v2")
	wal := e2eWAL(t)
	dirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}
	os.MkdirAll(dirs.Rootfs, 0o755)
	os.MkdirAll(dirs.ESP, 0o755)
	for _, f := range []string{filepath.Join(dirs.Rootfs, "rootfs-active.erofs"), filepath.Join(dirs.Rootfs, "rootfs-active.hash"),
		filepath.Join(dirs.ESP, "kernelcache-active.efi"), filepath.Join(dirs.ESP, "kernelcache-active.efi.sig")} {
		os.WriteFile(f, []byte("v1 "+filepath.Base(f)), 0o644)
	}
	if _, err := Stage(context.Background(), wal, base+"/manifest.json", "", rootPub, dirs); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	bootedAs(t, "v2", "verity-v2")
	health := t.TempDir()
	for i := 0; i < 3; i++ {
		if _, err := BootSuccess(wal, health, nil, dirs); err != nil {
			t.Fatalf("BootSuccess: %v", err)
		}
	}
	if v, _ := InstalledVersion(wal); v != "v2" {
		t.Fatalf("installed %q", v)
	}
	return wal, dirs, rootPub
}

func TestExportAndStageFrom(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal, dirs, rootPub := promotedMachine(t)
	if _, err := os.Stat(filepath.Join(dirs.Rootfs, "release", "v2", "manifest.json.sig")); err != nil {
		t.Fatalf("anchor not kept: %v", err)
	}
	out := filepath.Join(t.TempDir(), "release")
	m, err := ExportRelease(wal, dirs, rootPub, out)
	if err != nil || m.Version != "v2" {
		t.Fatalf("export: %v %+v", err, m)
	}

	other := e2eWAL(t)
	odirs := StageDirs{Rootfs: filepath.Join(t.TempDir(), "rootfs"), ESP: filepath.Join(t.TempDir(), "esp")}
	if _, err := StageFrom(context.Background(), other, out, rootPub, odirs); err != nil {
		t.Fatalf("StageFrom: %v", err)
	}
	d, _ := deployment.Load(other)
	if d.RootFS.Pending != "v2" || d.RootFS.PendingHash != "verity-v2" {
		t.Fatalf("not staged: %+v", d.RootFS)
	}
	want, _ := os.ReadFile(filepath.Join(dirs.Rootfs, "rootfs-active.erofs"))
	got, _ := os.ReadFile(filepath.Join(odirs.Rootfs, "rootfs-next.erofs"))
	if len(want) == 0 || !bytes.Equal(want, got) {
		t.Fatalf("rootfs differs")
	}
	if _, err := os.Stat(filepath.Join(odirs.Rootfs, "release", "v2", "manifest.json")); err != nil {
		t.Fatalf("staged machine keeps no anchor: %v", err)
	}
}

func TestExportRefusesChangedSlot(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal, dirs, rootPub := promotedMachine(t)
	p := filepath.Join(dirs.ESP, "kernelcache-active.efi")
	os.Remove(p)
	os.WriteFile(p, []byte("changed kernel"), 0o644)
	if _, err := ExportRelease(wal, dirs, rootPub, t.TempDir()); err == nil || !strings.Contains(err.Error(), "kernelcache.efi") {
		t.Fatalf("changed slot exported: %v", err)
	}
}

func TestStageFromRefusesTampering(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	wal, dirs, rootPub := promotedMachine(t)
	out := filepath.Join(t.TempDir(), "release")
	if _, err := ExportRelease(wal, dirs, rootPub, out); err != nil {
		t.Fatal(err)
	}
	stageInto := func() error {
		w := e2eWAL(t)
		return func() error {
			_, err := StageFrom(context.Background(), w, out, rootPub, StageDirs{Rootfs: filepath.Join(t.TempDir(), "r"), ESP: filepath.Join(t.TempDir(), "e")})
			return err
		}()
	}
	data, _ := os.ReadFile(filepath.Join(out, "manifest.json"))
	os.WriteFile(filepath.Join(out, "manifest.json"), bytes.Replace(data, []byte(`"v2"`), []byte(`"v9"`), 1), 0o644)
	if err := stageInto(); err == nil {
		t.Fatal("changed manifest staged")
	}
	os.WriteFile(filepath.Join(out, "manifest.json"), data, 0o644)

	link := filepath.Join(out, "rootfs.erofs")
	os.Remove(link)
	os.WriteFile(link, []byte("other root"), 0o644)
	if err := stageInto(); err == nil {
		t.Fatal("changed root image staged")
	}
	os.Remove(link)
	os.Symlink(filepath.Join(dirs.Rootfs, "rootfs-active.erofs"), link)

	newer := filepath.Join(t.TempDir(), "deployment.json")
	deployment.New("dev-2", "v3").Save(newer)
	if _, err := StageFrom(context.Background(), newer, out, rootPub, StageDirs{Rootfs: filepath.Join(t.TempDir(), "r"), ESP: filepath.Join(t.TempDir(), "e")}); err == nil || !strings.Contains(err.Error(), "anti-rollback") {
		t.Fatalf("downgrade staged: %v", err)
	}
	if err := stageInto(); err != nil {
		t.Fatalf("restored release refused: %v", err)
	}
}
