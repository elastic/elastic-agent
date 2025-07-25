//go:build windows

package upgrade

import (
	"errors"

	"github.com/elastic/elastic-agent/pkg/core/logger"

	winSys "golang.org/x/sys/windows"
)

// ToDiskSpaceError returns a generic disk space error if the error is a disk space error
func ToDiskSpaceErrorFunc(log *logger.Logger) func(error) error {
	return func(err error) error {
		if errors.Is(err, winSys.ERROR_DISK_FULL) || errors.Is(err, winSys.ERROR_HANDLE_DISK_FULL) {
			log.Infof("ToDiskSpaceError detected disk space error: %v, returning ErrInsufficientDiskSpace", err)
			return ErrInsufficientDiskSpace
		}

		return err
	}
}
