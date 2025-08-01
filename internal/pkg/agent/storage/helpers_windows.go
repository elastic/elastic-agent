// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package storage

import (
	"errors"
	"syscall"
	"time"

	"github.com/elastic/elastic-agent-libs/file"
)

const saveRetryFrequency = 50 * time.Millisecond
const saveRetryDuration = 2 * time.Second

// On Windows platforms, rotate (rename) operations are retried if the error is an
// ACCESS_DENIED error, which can happen if the file is locked by another process.
func checkRotateErrorAndRetry(err error, dst, src string) bool {
	if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		return false
	}

	for start := time.Now(); time.Since(start) < saveRetryDuration; time.Sleep(saveRetryFrequency) {
		err := file.SafeFileRotate(dst, src)
		if err == nil {
			// Rotate succeeded
			return true
		}

		if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			// Save failed due to an error that is not ACCESS_DENIED. Immediately
			// indicate failure without retrying further.
			return false
		}

		// Keep retrying...
	}

	// We exhausted retries without succeeding, so indicate failure.
	return false
}
