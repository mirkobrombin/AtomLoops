package boot

import "testing"

func TestF2FSOptions(t *testing.T) {
	cases := []struct {
		size uint64
		want string
	}{
		{0, "gc_merge,atgc,nodiscard"},
		{64 << 30, "gc_merge,atgc,nodiscard,reserve_root=167772"},
		{1 << 40, "gc_merge,atgc,nodiscard,reserve_root=524288"},
	}
	for _, c := range cases {
		if got := F2FSOptions(c.size); got != c.want {
			t.Errorf("%d: %q, want %q", c.size, got, c.want)
		}
	}
}
