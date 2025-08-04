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
func saveConfigToStore(store storage.Store, reader io.Reader) error {
	var saveErr error
	retryableSaveFn := func() error {
		saveErr = store.Save(reader)
		if errors.Is(saveErr, syscall.ERROR_ACCESS_DENIED) {
			// Retryable error, so return it
			return saveErr
		}

		// saveErr is an error that should not be retried. Return nil to
		// signal to the retrier that it should not retry.
		return nil
	}

	// Set maximum overall duration for retries
	retryCtx, retryCancel := context.WithTimeout(context.Background(), saveRetryDuration)
	defer retryCancel()

	// Set constant interval between retries
	retryWithConstantBackoff := backoff.NewConstantBackOff(saveRetryInterval)

	// Retry save operation
	//nolint:errcheck // ignore returned error because we're interested in the error from the save operation, saveErr
	backoff.Retry(retryableSaveFn, backoff.WithContext(retryWithConstantBackoff, retryCtx))

	return saveErr
}
