// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package errors

import "errors"

var ErrInsufficientDiskSpace = errors.New("insufficient disk space")

func IsDiskSpaceError(err error) bool {
	for _, osErr := range OS_DiskSpaceErrors {
		if errors.Is(err, osErr) {
			return true
		}
	}

	return false
}
