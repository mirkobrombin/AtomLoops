package boot

import "strconv"

const (
	f2fsBlock       = 4096
	reserveRootMax  = 2 << 30
	reserveRootPart = 100
)

func F2FSOptions(size uint64) string {
	opts := "gc_merge,atgc,nodiscard"
	if size == 0 {
		return opts
	}
	reserve := min(size/reserveRootPart, reserveRootMax) / f2fsBlock
	return opts + ",reserve_root=" + strconv.FormatUint(reserve, 10)
}
