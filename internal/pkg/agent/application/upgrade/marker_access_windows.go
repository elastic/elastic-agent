// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// TODO: is there an upper limit for this timeout?
const markerAccessTimeout = 10 * time.Second
const markerAccessBackoffInitialInterval = 50 * time.Millisecond
const minMarkerAccessRetries = 5

// On Windows, readMarkerFile tries to read the marker file, retrying with
// randomized exponential backoff up to markerAccessTimeout duration. This retry
// mechanism is necessary since the marker file could be accessed by multiple
// processes (the Upgrade Watcher and the main Agent process) at the same time,
// which could fail on Windows.
func readMarkerFile(markerFile string) ([]byte, error) {
	if _, err := os.Stat(markerFile); errors.Is(err, os.ErrNotExist) {
		// marker doesn't exist, nothing to do
		return nil, nil
	}
	var markerFileBytes []byte
	readFn := func() error {
		fileLock, err := newMarkerFileLocker(markerFile)
		if err != nil {
			return fmt.Errorf("creating update marker locker for reading: %w", err)
		}

		err = fileLock.Lock()
		if err != nil {
			return fmt.Errorf("locking update marker file %q for reading: %w", markerFile, err)
		}

		defer func(fileLock Locker) {
			errUnlock := fileLock.Unlock()
			if errUnlock != nil {
				err = errors.Join(err, fmt.Errorf("unlocking marker file after reading: %w", errUnlock))
			}
		}(fileLock)

		markerFileBytes, err = os.ReadFile(markerFile)
		if errors.Is(err, os.ErrNotExist) {
			// marker doesn't exist, nothing to do
			return nil
		}

		return err
	}

	if err := accessMarkerFileWithRetries(readFn); err != nil {
		return nil, fmt.Errorf("failed to read upgrade marker file [%s] despite retrying: %w", markerFile, err)
	}

	return markerFileBytes, nil
}

// On Windows, writeMarkerFile tries to write the marker file, retrying with
// randomized exponential backoff up to markerAccessTimeout duration. This retry
// mechanism is necessary since the marker file could be accessed by multiple
// processes (the Upgrade Watcher and the main Agent process) at the same time,
// which could fail on Windows.
func writeMarkerFile(markerFile string, markerBytes []byte, shouldFsync bool) error {
	writeFn := func() error {
		fileLock, err := newMarkerFileLocker(markerFile)
		if err != nil {
			return fmt.Errorf("creating update marker locker for writing: %w", err)
		}

		err = fileLock.Lock()
		if err != nil {
			return fmt.Errorf("locking update marker file %q for writing: %w", markerFile, err)
		}

		defer func(fileLock Locker) {
			errUnlock := fileLock.Unlock()
			if errUnlock != nil {
				err = errors.Join(err, fmt.Errorf("unlocking marker file after writing: %w", errUnlock))
			}
		}(fileLock)
		return writeMarkerFileCommon(markerFile, markerBytes, shouldFsync)
	}

	if err := accessMarkerFileWithRetries(writeFn); err != nil {
		return fmt.Errorf("failed to write upgrade marker file [%s] despite retrying: %w", markerFile, err)
	}

	return nil
}

func accessMarkerFileWithRetries(accessFn func() error) error {
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = markerAccessBackoffInitialInterval
	expBackoff.MaxInterval = markerAccessTimeout / minMarkerAccessRetries
	expBackoff.MaxElapsedTime = markerAccessTimeout

	ctx, cancel := context.WithTimeout(context.Background(), markerAccessTimeout)
	defer cancel()

	expBackoffWithTimeout := backoff.WithContext(expBackoff, ctx)
	start := time.Now()

	var duration time.Duration
	var count int
	var err error
	if err = accessFn(); err == nil {
		return nil
	}

	for duration = expBackoffWithTimeout.NextBackOff(); duration != backoff.Stop; duration = expBackoffWithTimeout.NextBackOff() {
		time.Sleep(duration)

		if err = accessFn(); err == nil {
			return nil
		}

		count++
	}

	return fmt.Errorf("could not write narker after %s and %d retries. Last error: %w",
		time.Since(start), count, err)
}
