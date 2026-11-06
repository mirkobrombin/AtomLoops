package boot

import (
	"errors"
	"os/exec"
	"strings"
)

// F2FSChecker is where the initramfs carries fsck.f2fs.
const F2FSChecker = "/sbin/fsck.f2fs"

// accountingChecks are the fsck.f2fs checks whose failure means only that the
// checkpoint or the segment table disagrees with the tree. Fixing them
// rewrites counters and segment types; no file, inode or directory entry is
// touched.
var accountingChecks = []string{
	"SIT valid block bitmap checking",
	"valid_block_count matching with CP",
	"valid_node_count matching with CP (de lookup)",
	"valid_node_count matching with CP (nat lookup)",
	"valid_inode_count matched with CP",
	"free segment_count matched with CP",
	"next block offset is free",
	"other corrupted bugs",
}

// tableOnly are the fsck.f2fs reports about the segment table that the
// checker rebuilds from the node tree. fsck.f2fs prints them and carries on:
// the node or block they name is still counted, so fixing them drops nothing.
// Any other assertion makes a repair the user's decision.
var tableOnly = [][]string{
	{"--> SIT bitmap is 0x0. "},
	{"--> Incorrect curseg [", "type(SIT)"},
	{"--> Wrong segment type ["},
}

func tableOnlyReport(line string) bool {
	for _, parts := range tableOnly {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(line, p)
		}
		if all {
			return true
		}
	}
	return false
}

// CheckVerdict is what a read-only fsck.f2fs run says about a partition.
type CheckVerdict int

const (
	// CheckClean means the checker found nothing to fix.
	CheckClean CheckVerdict = iota
	// CheckAccounting means every failure is a counter the checker can
	// rewrite without removing data.
	CheckAccounting
	// CheckNeedsUser means a fix could remove files or the output is not
	// understood; only the user may decide.
	CheckNeedsUser
)

func (v CheckVerdict) String() string {
	switch v {
	case CheckClean:
		return "clean"
	case CheckAccounting:
		return "accounting"
	}
	return "needs-user"
}

// ClassifyF2FSCheck reads the output and exit status of fsck.f2fs --dry-run
// and returns the verdict with the failed checks it found.
func ClassifyF2FSCheck(out string, exit int) (CheckVerdict, []string) {
	var failed []string
	risky := false
	for _, line := range strings.Split(out, "\n") {
		if (strings.Contains(line, "[ASSERT]") || strings.Contains(line, "[FIX]")) && !tableOnlyReport(line) {
			risky = true
		}
		if !strings.HasPrefix(line, "[FSCK] ") || !strings.Contains(line, "[Fail]") {
			continue
		}
		name := strings.TrimPrefix(line, "[FSCK] ")
		name = strings.TrimSpace(name[:strings.Index(name, "[Fail]")])
		failed = append(failed, name)
		if !contains(accountingChecks, name) {
			risky = true
		}
	}
	switch {
	case exit == 0 && len(failed) == 0 && !risky:
		return CheckClean, nil
	case exit != 0 && len(failed) > 0 && !risky:
		return CheckAccounting, failed
	}
	return CheckNeedsUser, failed
}

// Repair is the record of one boot-time repair attempt on a data partition.
type Repair struct {
	Dev     string
	Verdict CheckVerdict
	Failed  []string
	Before  string
	Fix     string
	After   string
	Fixed   bool
}

// Runner runs a program and returns its combined output and exit status.
type Runner func(name string, args ...string) (string, int)

// RunCommand is the Runner that executes on the running system.
func RunCommand(name string, args ...string) (string, int) {
	out, err := exec.Command(name, args...).CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	}
	return string(out) + err.Error(), -1
}

// RepairF2FS checks dev without writing and repairs it only when every
// failure is accounting. The repair counts only when a second read-only check
// comes back clean.
func RepairF2FS(dev string, run Runner) Repair {
	r := Repair{Dev: dev}
	out, exit := run(F2FSChecker, "--dry-run", "-f", dev)
	r.Before = out
	r.Verdict, r.Failed = ClassifyF2FSCheck(out, exit)
	Logf("data check %s: %s %v", dev, r.Verdict, r.Failed)
	if r.Verdict != CheckAccounting {
		return r
	}
	r.Fix, _ = run(F2FSChecker, "-f", "-y", dev)
	out, exit = run(F2FSChecker, "--dry-run", "-f", dev)
	r.After = out
	after, _ := ClassifyF2FSCheck(out, exit)
	r.Fixed = after == CheckClean
	Logf("data repair %s: fixed=%v", dev, r.Fixed)
	return r
}
