package boot

import "testing"

func TestRankPairsMapsTheSignedPairFirst(t *testing.T) {
	const next = "1111111111111111111111111111111111111111111111111111111111111111"
	const active = "2222222222222222222222222222222222222222222222222222222222222222"
	roots := map[string]string{"/dev/loop2": active, "/dev/loop3": next}
	wants := map[string]uint64{"/dev/loop2": 100, "/dev/loop3": 200}
	sizes := map[string]uint64{"/dev/loop0": 100, "/dev/loop1": 200}
	ops := Ops{
		HashRoot: func(dev string) (string, uint64) { return roots[dev], wants[dev] },
		DevBytes: func(dev string) uint64 { return sizes[dev] },
	}
	cfg := &Config{RootHash: next}
	pairs := rankPairs(cfg, ops, []string{"/dev/loop0", "/dev/loop1"}, []string{"/dev/loop2", "/dev/loop3"})
	if len(pairs) != 4 {
		t.Fatalf("got %d pairs", len(pairs))
	}
	if pairs[0] != [2]string{"/dev/loop1", "/dev/loop3"} {
		t.Fatalf("first pair %v, want the next data and hash", pairs[0])
	}
	if pairs[1][1] != "/dev/loop3" {
		t.Fatalf("second pair %v, want the signed hash with the other data", pairs[1])
	}
	for _, p := range pairs[2:] {
		if p[1] != "/dev/loop2" {
			t.Fatalf("pair %v names another root but is not last", p)
		}
	}
}

func TestRankPairsKeepsOrderWithoutRootInformation(t *testing.T) {
	pairs := rankPairs(&Config{RootHash: "x"}, Ops{}, []string{"d0", "d1"}, []string{"h0"})
	if pairs[0] != [2]string{"d0", "h0"} || pairs[1] != [2]string{"d1", "h0"} {
		t.Fatalf("unexpected order %v", pairs)
	}
}

func TestSelectVerifiedOpensOnlyTheSignedPairOnATrialBoot(t *testing.T) {
	const next = "1111111111111111111111111111111111111111111111111111111111111111"
	var opened [][2]string
	ops := Ops{
		HashRoot: func(dev string) (string, uint64) {
			if dev == "h-next" {
				return next, 2
			}
			return "2222222222222222222222222222222222222222222222222222222222222222", 1
		},
		DevBytes:    func(dev string) uint64 { return map[string]uint64{"d-active": 1, "d-next": 2}[dev] },
		CloseVerity: func(string) error { return nil },
		OpenVerity: func(name, d, h, root string) (string, error) {
			opened = append(opened, [2]string{d, h})
			return "/dev/mapper/" + name, nil
		},
		HasEROFS: func(string) bool { return true },
	}
	m := &Media{SlotDatas: []string{"d-active", "d-next"}, SlotHashes: []string{"h-active", "h-next"}}
	root := selectVerified(&Config{RootHash: next}, m, ops)
	if root == nil || root.Data != "d-next" || root.Hash != "h-next" {
		t.Fatalf("selected %+v", root)
	}
	if len(opened) != 1 {
		t.Fatalf("mapped %v, want only the signed pair", opened)
	}
}
