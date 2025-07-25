//go:build !windows

package upgrade

import (
	"errors"
	"syscall"
)

// ToDiskSpaceError returns a generic disk space error if the error is a disk space error
func ToDiskSpaceError(err error) error {
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return insufficientDiskSpaceErr
	}

	return err
}
