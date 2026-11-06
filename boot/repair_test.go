package boot

import (
	"os"
	"reflect"
	"testing"
)

func fsckOutput(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/fsck-f2fs-" + name + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestClassifyF2FSCheck(t *testing.T) {
	for _, c := range []struct {
		name   string
		exit   int
		want   CheckVerdict
		failed []string
	}{
		{"clean", 0, CheckClean, nil},
		{"accounting", 1, CheckAccounting, []string{
			"valid_node_count matching with CP (de lookup)",
			"valid_node_count matching with CP (nat lookup)",
		}},
		{"risky", 255, CheckNeedsUser, nil},
		{"accounting-after", 0, CheckClean, nil},
	} {
		got, failed := ClassifyF2FSCheck(fsckOutput(t, c.name), c.exit)
		if got != c.want {
			t.Errorf("%s: verdict %s, want %s", c.name, got, c.want)
		}
		if c.failed != nil && !reflect.DeepEqual(failed, c.failed) {
			t.Errorf("%s: failed %q, want %q", c.name, failed, c.failed)
		}
	}
	if v, _ := ClassifyF2FSCheck("Invalid SB CRC offset\n", 255); v != CheckNeedsUser {
		t.Errorf("unreadable superblock: %s", v)
	}
	if v, _ := ClassifyF2FSCheck(fsckOutput(t, "clean"), 1); v != CheckNeedsUser {
		t.Errorf("a failing exit with no failed check: %s", v)
	}
}

func TestRepairF2FS(t *testing.T) {
	var calls [][]string
	script := func(outputs ...string) Runner {
		calls = nil
		return func(name string, args ...string) (string, int) {
			calls = append(calls, append([]string{name}, args...))
			out := fsckOutput(t, outputs[len(calls)-1])
			if out == fsckOutput(t, "accounting") {
				return out, 1
			}
			if out == fsckOutput(t, "risky") {
				return out, 255
			}
			return out, 0
		}
	}
	r := RepairF2FS("/dev/vda2", script("accounting", "clean", "accounting-after"))
	if !r.Fixed || r.Verdict != CheckAccounting || len(calls) != 3 {
		t.Fatalf("accounting damage: fixed=%v verdict=%s calls=%v", r.Fixed, r.Verdict, calls)
	}
	if !reflect.DeepEqual(calls[1], []string{F2FSChecker, "-f", "-y", "/dev/vda2"}) {
		t.Errorf("fix call %v", calls[1])
	}
	r = RepairF2FS("/dev/vda2", script("accounting", "clean", "accounting"))
	if r.Fixed {
		t.Error("a repair whose recheck still fails counts as fixed")
	}
	r = RepairF2FS("/dev/vda2", script("risky"))
	if r.Fixed || r.Verdict != CheckNeedsUser || len(calls) != 1 {
		t.Errorf("risky damage was touched: fixed=%v verdict=%s calls=%v", r.Fixed, r.Verdict, calls)
	}
	for _, c := range calls {
		if c[1] != "--dry-run" {
			t.Errorf("risky damage ran %v", c)
		}
	}
}
