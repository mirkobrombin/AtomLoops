package sealedlog

import (
	"fmt"
	"strconv"
	"strings"
)

// Component identifies the writer of a record. Zero is reserved as padding.
type Component uint8

// Code is an event of a component. Codes below CodeLocal are shared by every
// component; the rest are defined per component. Zero is reserved as padding.
type Code uint8

// Components Atom Loops writes itself. The numbers left free belong to the
// system, which names them in its dictionary file.
const (
	CompLoader      Component = 1
	CompKernelLinux Component = 2
	CompKernelEarly Component = 3
	CompAtomInit    Component = 5
	CompAtomd       Component = 6
	CompUpdated     Component = 7
	CompLogd        Component = 21
)

// Family is the set of events a component speaks.
type Family uint8

const (
	FamilyNone Family = iota
	FamilyLoader
	FamilyKernel
	FamilyInit
	FamilyOTA
	FamilySession
	FamilyBoot
)

var familyNames = map[string]Family{
	"-": FamilyNone, "loader": FamilyLoader, "kernel": FamilyKernel,
	"init": FamilyInit, "ota": FamilyOTA, "session": FamilySession, "boot": FamilyBoot,
}

type compInfo struct {
	name   string
	family Family
	user   bool
}

var components = map[Component]compInfo{
	CompLoader:      {"loader", FamilyLoader, false},
	CompKernelLinux: {"kernel-linux", FamilyKernel, false},
	CompKernelEarly: {"kernel-early", FamilyKernel, false},
	CompAtomInit:    {"atom-init", FamilyBoot, false},
	CompAtomd:       {"atomd", FamilyOTA, false},
	CompUpdated:     {"updated", FamilyOTA, false},
	CompLogd:        {"sealedlogd", FamilyNone, false},
}

// DefaultDictionary is where the system names its own components.
const DefaultDictionary = "/usr/share/sealedlog/components"

// LoadDictionary adds the components a system declares, one per line:
//
//	NUMBER NAME FAMILY [user]
//
// FAMILY is one of loader, kernel, init, ota, session, boot or "-". A component
// marked user may be logged by desktop users. Lines starting with # are
// skipped. The components of Atom Loops cannot be redefined.
func LoadDictionary(b []byte) error {
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if len(f) < 3 || len(f) > 4 || (len(f) == 4 && f[3] != "user") {
			return fmt.Errorf("sealedlog: dictionary line %d: want NUMBER NAME FAMILY [user]", i+1)
		}
		n, err := strconv.ParseUint(f[0], 10, 8)
		if err != nil || n == 0 {
			return fmt.Errorf("sealedlog: dictionary line %d: bad component number", i+1)
		}
		fam, ok := familyNames[f[2]]
		if !ok {
			return fmt.Errorf("sealedlog: dictionary line %d: unknown family %q", i+1, f[2])
		}
		c := Component(n)
		if old, ok := components[c]; ok && builtin(c) {
			if old.name != f[1] {
				return fmt.Errorf("sealedlog: dictionary line %d: component %d is %s", i+1, n, old.name)
			}
			continue
		}
		components[c] = compInfo{name: f[1], family: fam, user: len(f) == 4}
	}
	return nil
}

func builtin(c Component) bool {
	switch c {
	case CompLoader, CompKernelLinux, CompKernelEarly, CompAtomInit, CompAtomd, CompUpdated, CompLogd:
		return true
	}
	return false
}

func (c Component) String() string {
	if i, ok := components[c]; ok {
		return i.name
	}
	return fmt.Sprintf("component-%d", uint8(c))
}

// ComponentByName returns the component with the given dictionary name.
func ComponentByName(name string) (Component, bool) {
	for c, i := range components {
		if i.name == name {
			return c, true
		}
	}
	return 0, false
}

// FamilyOf returns the events component c speaks.
func FamilyOf(c Component) Family {
	return components[c].family
}

// UserComponent reports whether desktop users may log as c.
func UserComponent(c Component) bool {
	return components[c].user
}

const (
	CodeStart Code = 1 + iota
	CodeReady
	CodeStop
	CodeFail
	CodeCrash
	CodeRestart
	CodeTimeout
	CodeDenied
	CodeWarn
)

// CodeBlob is the one record that carries bytes instead of codes.
const CodeBlob Code = 31

// CodeLocal is the first component-specific code.
const CodeLocal Code = 32

const (
	LoaderBootStart Code = CodeLocal + iota
	LoaderSlotChosen
	LoaderTrial
	LoaderSignatureBad
	LoaderRollbackRefused
	LoaderSlotMissing
	LoaderChainload
	LoaderChainloadFail
	LoaderFallback
	LoaderHalted
	LoaderRecovery
	LoaderChooser
	LoaderMeasured
	LoaderUnlockArmed
)

const (
	KernelStage Code = CodeLocal + iota
	KernelRootMounted
	KernelInitStarted
	KernelInitExit
	KernelPanic
	KernelOops
	KernelWatchdog
	KernelSuspend
	KernelResume
	KernelThermal
	KernelTpmLaunch
	KernelDriverFail
)

const (
	InitTarget Code = CodeLocal + iota
	InitUnitFail
	InitUnitRestart
	InitShutdown
)

const (
	OtaStaged Code = CodeLocal + iota
	OtaPromoted
	OtaRollback
	OtaHealthy
	OtaDownloadFail
	OtaVerifyFail
	OtaReboot
	OtaLiveApplied
	OtaLiveRollback
)

const (
	BootDiagnosis Code = CodeLocal + iota
	BootDataCheck
	BootDataRepair
)

const (
	SessionLogin Code = CodeLocal + iota
	SessionLoginFail
	SessionLogout
	SessionLock
	SessionAppCrash
	SessionFirstFrame
	SessionDiskError
	SessionBatteryCritical
)

var sharedCodeNames = [...]string{
	CodeStart:   "start",
	CodeReady:   "ready",
	CodeStop:    "stop",
	CodeFail:    "fail",
	CodeCrash:   "crash",
	CodeRestart: "restart",
	CodeTimeout: "timeout",
	CodeDenied:  "denied",
	CodeWarn:    "warn",
}

var familyCodeNames = map[Family][]string{
	FamilyLoader: {"boot-start", "slot-chosen", "trial", "signature-bad", "rollback-refused", "slot-missing",
		"chainload", "chainload-fail", "fallback", "halted", "recovery", "chooser", "measured", "unlock-armed"},
	FamilyKernel:  kernelNames,
	FamilyInit:    {"target", "unit-fail", "unit-restart", "shutdown"},
	FamilyOTA:     otaNames,
	FamilySession: sessionNames,
	FamilyBoot:    {"diagnosis", "data-check", "data-repair"},
}

var kernelNames = []string{"stage", "root-mounted", "init-started", "init-exit", "panic", "oops", "watchdog",
	"suspend", "resume", "thermal", "tpm-launch", "driver-fail"}

var otaNames = []string{"staged", "promoted", "rollback", "healthy", "download-fail", "verify-fail", "reboot", "live-applied", "live-rollback"}

var sessionNames = []string{"login", "login-fail", "logout", "lock", "app-crash", "first-frame", "disk-error",
	"battery-critical"}

// CodeName returns the dictionary word for code as written by comp.
func CodeName(comp Component, code Code) string {
	if code == CodeBlob {
		return "blob"
	}
	if code < CodeLocal {
		if int(code) < len(sharedCodeNames) && sharedCodeNames[code] != "" {
			return sharedCodeNames[code]
		}
		return fmt.Sprintf("code-%d", uint8(code))
	}
	if names := familyCodeNames[FamilyOf(comp)]; int(code-CodeLocal) < len(names) {
		return names[code-CodeLocal]
	}
	return fmt.Sprintf("code-%d", uint8(code))
}

// CodeByName resolves a dictionary word for comp.
func CodeByName(comp Component, name string) (Code, bool) {
	for i, n := range sharedCodeNames {
		if n == name && n != "" {
			return Code(i), true
		}
	}
	for i, n := range familyCodeNames[FamilyOf(comp)] {
		if n == name {
			return CodeLocal + Code(i), true
		}
	}
	return 0, false
}
