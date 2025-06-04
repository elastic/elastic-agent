// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package filelock

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/flock"
)

var (
	ErrZeroTimeout = errors.New("must specify a non-zero timeout for a blocking file locker")
	ErrNotLocked   = errors.New("file not locked")
)

// FileLocker is a thin wrapper around "github.com/gofrs/flock" Flock providing both blocking and non-blocking file locking.
// It exposes a simplified Lock*/Unlock interface and by default is non-blocking.
// If it's not possible to acquire a lock on the specified file ErrNotLocked (directly or wrapped in another error) is returned by default.
// It's possible to customize FileLocker behavior specifying one or more FileLockerOption at creation time
type FileLocker struct {
	fileLock             *flock.Flock
	blocking             bool
	timeout              time.Duration
	customNotLockedError error
}

func NewFileLocker(lockFilePath string, opts ...FileLockerOption) (*FileLocker, error) {
	flocker := &FileLocker{fileLock: flock.New(lockFilePath)}
	for _, opt := range opts {
		if err := opt(flocker); err != nil {
			return nil, fmt.Errorf("applying options to new file locker: %w", err)
		}
	}
	return flocker, nil
}

func (fl *FileLocker) Lock() error {
	return fl.LockContext(context.Background())
}

func (fl *FileLocker) LockContext(ctx context.Context) error {
	var locked bool
	var err error

	if fl.blocking {
		timeoutCtx, cancel := context.WithTimeout(ctx, fl.timeout)
		defer cancel()
		locked, err = fl.fileLock.TryLockContext(timeoutCtx, time.Second)
	} else {
		locked, err = fl.fileLock.TryLock()
	}

	if err != nil {
		return fmt.Errorf("locking %s: %w", fl.fileLock.Path(), err)
	}
	if !locked {
		if fl.customNotLockedError != nil {
			return fmt.Errorf("failed locking %s: %w", fl.fileLock.Path(), fl.customNotLockedError)
		}
		return fmt.Errorf("failed locking %s: %w", fl.fileLock.Path(), ErrNotLocked)
	}
	return nil
}

func (fl *FileLocker) Unlock() error {
	return fl.fileLock.Unlock()
}

type FileLockerOption func(locker *FileLocker) error

// WithCustomLockedError will set a custom error to be returned
func WithCustomNotLockedError(customError error) FileLockerOption {
	return func(locker *FileLocker) error {
		locker.customNotLockedError = customError
		return nil
	}
}

func WithTimeout(timeout time.Duration) FileLockerOption {
	return func(locker *FileLocker) error {

		if timeout == 0 {
			return ErrZeroTimeout
		}

		locker.blocking = true
		locker.timeout = timeout

		return nil
	}
}
