package deployment

import (
	"errors"
	"syscall"
)

// isEINVAL reports whether err is EINVAL, which some filesystems return from a
// directory fsync even though the preceding rename is durable.
func isEINVAL(err error) bool { return errors.Is(err, syscall.EINVAL) }
