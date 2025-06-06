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
// It's possible to customize FileLocker behavior specifying one or more FileLockerOption at creation time.
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

// Lock() will attempt to lock the configured lockfile. Depending on the options specified at FileLocker creation this
// call can be blocking or non-blocking. In order to use a blocking FileLocker a timeout must be specified at creation
// specifying WithTimeout() option.
// Even in case of a blocking FileLocker the maximum duration of the locking attempt will be the timeout specified at creation.
// If no lock can be acquired ErrNotLocked error will be returned by default, unless a custom "not locked" error has been
// specified with WithCustomNotLockedError at creation.
func (fl *FileLocker) Lock() error {
	return fl.LockContext(context.Background())
}

// LockWithContext() will attempt to lock the configured lockfile. It has the same semantics as Lock(), additionally it
// allows passing a context as an argument to back out of locking attempts when context expires (useful in case of a
// blocking FileLocker)
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

func (fl *FileLocker) Locked() bool {
	return fl.fileLock.Locked()
}

type FileLockerOption func(locker *FileLocker) error

// WithCustomNotLockedError will set a custom error to be returned when it's not possible to acquire a lock
func WithCustomNotLockedError(customError error) FileLockerOption {
	return func(locker *FileLocker) error {
		locker.customNotLockedError = customError
		return nil
	}
}

// WithTimeout will set the FileLocker to be blocking and will enforce a non-zero timeout.
// If a zero timeout is passed this option will error out, failing the FileLocker creation.
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
