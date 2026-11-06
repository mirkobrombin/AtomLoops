package boot

import (
	"os"
	"reflect"
	"strings"
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
		{"sit-only", 1, CheckAccounting, []string{
			"SIT valid block bitmap checking",
			"free segment_count matched with CP",
			"other corrupted bugs",
		}},
		{"no-checkpoint", 255, CheckUnrepairable, nil},
		{"no-superblock", 255, CheckUnrepairable, nil},
	} {
		got, failed := ClassifyF2FSCheck(fsckOutput(t, c.name), c.exit)
		if got != c.want {
			t.Errorf("%s: verdict %s, want %s", c.name, got, c.want)
		}
		if c.failed != nil && !reflect.DeepEqual(failed, c.failed) {
			t.Errorf("%s: failed %q, want %q", c.name, failed, c.failed)
		}
	}
	mixed := fsckOutput(t, "sit-only") + "[ASSERT] (sanity_check_nid: 429)  --> nid[0xa] nat_entry->ino[0x0] footer.ino[0xa]\n"
	if v, _ := ClassifyF2FSCheck(mixed, 1); v != CheckNeedsUser {
		t.Errorf("segment table damage with a node assertion: %s", v)
	}
	ssa := "[ASSERT] (fsck_chk_curseg_info:3163)  --> Incorrect curseg [4]: segno [0x43c] type(SSA) [0]\n[FSCK] other corrupted bugs                           [Fail]\n"
	if v, _ := ClassifyF2FSCheck(ssa, 1); v != CheckNeedsUser {
		t.Errorf("summary type damage: %s", v)
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

func TestRepairReportKeepsBothEndsOfALongOutput(t *testing.T) {
	long := "first" + strings.Repeat("x", 1<<20) + "last"
	rep := Repair{Dev: "/dev/vda2", Verdict: CheckAccounting, Fixed: true, Fix: long}.Report("SINTYREPAIR")
	if len(rep) > 4*reportSection {
		t.Fatalf("report is %d bytes", len(rep))
	}
	for _, want := range []string{"SINTYREPAIR dev=/dev/vda2 verdict=accounting fixed=true", "first", "last", "bytes left out"} {
		if !strings.Contains(rep, want) {
			t.Fatalf("report lacks %q", want)
		}
	}
}
