package deployment

import "testing"

func TestPickBootTargetSlots(t *testing.T) {
	cases := []struct {
		name   string
		build  func() *Deployment
		wantR  Slot
		wantKC Slot
	}{
		{
			name:   "stable -> active",
			build:  func() *Deployment { return New("d", "v1") },
			wantR:  SlotActive,
			wantKC: SlotActive,
		},
		{
			name: "candidate with budget -> next",
			build: func() *Deployment {
				d := New("d", "v1")
				d.Deploy("v2")
				return d
			},
			wantR:  SlotNext,
			wantKC: SlotNext,
		},
		{
			name: "candidate out of budget with fallback -> prev",
			build: func() *Deployment {
				d := New("d", "v1")
				d.Deploy("v2")
				for i := 0; i < 3; i++ {
					d.DecrementBootAttempt()
				}
				return d
			},
			wantR:  SlotPrev,
			wantKC: SlotPrev,
		},
		{
			name: "candidate out of budget, no fallback -> recovery",
			build: func() *Deployment {
				d := New("d", "v1")
				d.RootFS.LastKnownGood = ""
				d.RootFS.Rollback = ""
				d.Deploy("v2")
				for i := 0; i < 3; i++ {
					d.DecrementBootAttempt()
				}
				return d
			},
			wantR:  SlotRecovery,
			wantKC: SlotRecovery,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, kc, err := PickBootTarget(c.build())
			if err != nil {
				t.Fatal(err)
			}
			if r != c.wantR || kc != c.wantKC {
				t.Errorf("slots = %s,%s; want %s,%s", r, kc, c.wantR, c.wantKC)
			}
			if r != kc {
				t.Errorf("1:1 coupling broken: rootfs slot %s != kc slot %s", r, kc)
			}
		})
	}
	if _, _, err := PickBootTarget(nil); err == nil {
		t.Error("PickBootTarget(nil) should error")
	}
}
