package upgrade

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
