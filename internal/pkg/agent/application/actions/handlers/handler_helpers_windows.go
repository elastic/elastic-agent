// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package handlers

import (
	"context"
	"errors"
	"io"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
)

const saveRetryInterval = 50 * time.Millisecond
const saveRetryDuration = 2 * time.Second

// saveConfigToStore saves the given configuration (reader) to the given store.
// On Windows platforms, the save operation is retried if the error is an
// ACCESS_DENIED error, which can happen if the file is locked by another process.
func saveConfigToStore(store storage.Store, reader io.ReadSeeker) error {
	retryableSaveFn := func() error {
		err := store.Save(reader)
		if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			// Retryable error, so reset reader position to start and return the error
			if _, seekErr := reader.Seek(0, io.SeekStart); seekErr != nil {
				// Could not reset reader position; we can no longer retry
				return backoff.Permanent(errors.Join(err, seekErr))
			}

			return err
		}

		if err != nil {
			// Non-retryable error, so mark it as permanent
			return backoff.Permanent(err)
		}

		return nil
	}

	// Set maximum overall duration for retries
	retryCtx, retryCancel := context.WithTimeout(context.Background(), saveRetryDuration)
	defer retryCancel()

	// Set constant interval between retries
	retryWithConstantBackoff := backoff.NewConstantBackOff(saveRetryInterval)

	// Retry save operation
	return backoff.Retry(retryableSaveFn, backoff.WithContext(retryWithConstantBackoff, retryCtx))
}
