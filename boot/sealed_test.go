package boot

import (
	"testing"

	"github.com/mirkobrombin/atomloops/internal/sealedlog"
)

func TestInitRecordsWaitInTheEFIVariable(t *testing.T) {
	old := sealedlog.EFIVarDir
	sealedlog.EFIVarDir = t.TempDir()
	defer func() { sealedlog.EFIVarDir = old }()

	LogDataRepair(Repair{Verdict: CheckNeedsUser})
	LogDiagnosis(Diagnosis{Code: "B03", Phase: "data-mount"})

	b, err := sealedlog.ReadEFIVar(sealedlog.VarInit)
	if err != nil {
		t.Fatal(err)
	}
	e, err := sealedlog.ParseEarly(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Payload.Records) != 2 {
		t.Fatalf("records = %+v", e.Payload.Records)
	}
	check, diag := e.Payload.Records[0], e.Payload.Records[1]
	if sealedlog.CodeName(check.Component, check.Code) != "data-check" || check.Args[0] != uint64(CheckNeedsUser) || check.Args[1] != 0 {
		t.Errorf("check record = %+v", check)
	}
	if sealedlog.CodeName(diag.Component, diag.Code) != "diagnosis" || diag.Args[0] != 3 || diag.Args[1] != 0 {
		t.Errorf("diagnosis record = %+v", diag)
	}
	if diag.Component.String() != "atom-init" {
		t.Errorf("component = %s", diag.Component)
	}
}
