// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package errors

import (
	"errors"

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// ToDiskSpaceError returns a generic disk space error if the error is a disk space error
func ToDiskSpaceErrorFunc(log *logger.Logger) func(error) error {
	return func(err error) error {
		if errors.Is(err, windows.ERROR_DISK_FULL) || errors.Is(err, windows.ERROR_HANDLE_DISK_FULL) {
			if log != nil {
				log.Infof("ToDiskSpaceError detected disk space error: %v, returning ErrInsufficientDiskSpace", err)
			}
			return ErrInsufficientDiskSpace
		}

		return err
	}
}
