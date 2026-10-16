package otad

import "testing"

func TestSameRelease(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v9002", "9002", true},
		{"v9002", "v9002", true},
		{"9002", "9002", true},
		{"v9002", "v9001", false},
		{"v9002", "vv9002", false},
	}
	for _, c := range cases {
		if got := sameRelease(c.a, c.b); got != c.want {
			t.Errorf("sameRelease(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
