// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package errors

import (
	"errors"
	"strings"
)

var ErrFetchUpgradeSize = errors.New("failed to fetch exact upgrade size")

type DiskSpaceLowError []string

func (e DiskSpaceLowError) Error() string {
	msg := "insufficient disk space for upgrade"
	if len(e) == 0 {
		return msg
	}
	return msg + ": " + strings.Join(e, ", ")
}

func IsDiskSpaceLowError(err error) bool {
	var diskSpaceLowErr DiskSpaceLowError
	if errors.As(err, &diskSpaceLowErr) {
		return true
	}

	// Errors indicating we are currently out of disk space
	for _, osErr := range OS_DiskSpaceErrors {
		if errors.Is(err, osErr) {
			return true
		}
	}

	return false
}
