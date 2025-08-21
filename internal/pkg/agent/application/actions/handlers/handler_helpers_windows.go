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
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const saveRetryInterval = 50 * time.Millisecond
const saveRetryDuration = 2 * time.Second

// saveConfigToStore saves the given configuration (reader) to the given store.
// On Windows platforms, the save operation is retried if the error is an
// ACCESS_DENIED error, which can happen if the file is locked by another process.
func saveConfigToStore(store storage.Store, reader io.ReadSeeker, log *logger.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), saveRetryDuration)
	defer cancel()

	bo := backoff.WithContext(backoff.NewConstantBackOff(saveRetryInterval), ctx)

	return backoff.Retry(func() error {
		err := store.Save(reader)
		if err == nil {
			// Save succeeded
			return nil
		}

		if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			// Save failed due to an error that is not ACCESS_DENIED. Immediately
			// indicate failure without retrying further.
			log.Debugf("Saving configuration to store failed: %v. Not retrying.", err)
			return backoff.Permanent(err)
		}

		if _, seekErr := reader.Seek(0, io.SeekStart); seekErr != nil {
			log.Debugf("Saving configuration to store failed: %v. Failed to reset reader: %v. Not retrying.", err, seekErr)
			return backoff.Permanent(errors.Join(err, seekErr))
		}

		log.Debugf("Saving configuration to store failed: %v. Retrying...", err)
		return err
	}, bo)
}
