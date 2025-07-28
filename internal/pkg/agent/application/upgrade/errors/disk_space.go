// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package errors

import (
	"errors"
)

const insufficientDiskSpaceErrorStr = "insufficient disk space"

var ErrInsufficientDiskSpace = &InsufficientDiskSpaceError{Err: errors.New(insufficientDiskSpaceErrorStr)}

type InsufficientDiskSpaceError struct {
	Err error
}

func (e *InsufficientDiskSpaceError) Error() string {
	return e.Err.Error()
}

func (e *InsufficientDiskSpaceError) Unwrap() error {
	return e.Err
}

func (e *InsufficientDiskSpaceError) Is(target error) bool {
	_, ok := target.(*InsufficientDiskSpaceError)
	return ok
}
