//go:build windows

package upgrade

import (
	"errors"

	winSys "golang.org/x/sys/windows"
)

// ToDiskSpaceError returns a generic disk space error if the error is a disk space error
func ToDiskSpaceError(err error) error {
	if errors.Is(err, winSys.ERROR_DISK_FULL) || errors.Is(err, winSys.ERROR_HANDLE_DISK_FULL) {
		return errors.New(insufficientDiskSpaceErrorStr)
	}

	return err
}
