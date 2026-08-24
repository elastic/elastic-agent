// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"

	"github.com/cenkalti/backoff/v7"
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
	var markerFileBytes []byte
	readFn := func() error {
		var err error
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

	ctx, cancel := context.WithTimeout(context.Background(), markerAccessTimeout)
	defer cancel()

	start := time.Now()
	var count int
	var lastErr error
	_, retryErr := backoff.Retry(ctx, func() (struct{}, error) {
		lastErr = accessFn()
		if lastErr != nil {
			count++
		}
		return struct{}{}, lastErr
	}, backoff.WithBackOff(expBackoff), backoff.WithMaxElapsedTime(markerAccessTimeout))
	if retryErr != nil {
		return fmt.Errorf("could not write narker after %s and %d retries. Last error: %w",
			time.Since(start), count, lastErr)
	}
	return nil
}
