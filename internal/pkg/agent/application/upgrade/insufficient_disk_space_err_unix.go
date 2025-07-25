//go:build !windows

package upgrade

import (
	"errors"
	"syscall"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// ToDiskSpaceError returns a generic disk space error if the error is a disk space error
func ToDiskSpaceErrorFunc(log *logger.Logger) func(error) error {
	return func(err error) error {
		if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
			log.Infof("ToDiskSpaceError detected disk space error: %v, returning ErrInsufficientDiskSpace", err)
			return ErrInsufficientDiskSpace
		}

		return err
	}
}
