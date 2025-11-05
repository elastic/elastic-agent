// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package enroll

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// fakeBackoff allows controlling the sequence of Wait() return values for tests.
type fakeBackoff struct {
	results []bool
}

func (f *fakeBackoff) Wait() bool {
	return true
}

func (f *fakeBackoff) NextWait() (d time.Duration) { return 0 }
func (f *fakeBackoff) Reset()                      {}

func TestRetryEnroll_SucceedsAfterOneRetry(t *testing.T) {
	// initial error forces at least one retry
	initialErr := errors.New("initial failure")

	called := 0
	enrollFn := func() error {
		called++
		// succeed on first retry
		return nil
	}

	fb := &fakeBackoff{results: []bool{true}}

	l := logger.NewWithoutConfig("")

	err := retryEnroll(initialErr, 5, l, enrollFn, "http://localhost", fb)
	require.NoError(t, err)
	require.Equal(t, 1, called)
}

func TestRetryEnroll_BackoffStopsImmediately(t *testing.T) {
	initialErr := fmt.Errorf("network")
	called := 0
	expectedAttempts := 5
	enrollFn := func() error {
		called++
		return errors.New("still failing")
	}

	fb := &fakeBackoff{results: []bool{false}}

	l := logger.NewWithoutConfig("")

	err := retryEnroll(initialErr, expectedAttempts, l, enrollFn, "http://localhost", fb)
	require.Equal(t, expectedAttempts-1, called)
	require.Error(t, err)                  // error is expected
	require.NotErrorIs(t, err, initialErr) // subsequent failures are different
}

func TestRetryEnroll_BreaksOnContextCanceled(t *testing.T) {
	// When err is context.Canceled, retryEnroll should return immediately
	cancelErr := context.Canceled
	called := 0
	enrollFn := func() error {
		called++
		return nil
	}
	fb := &fakeBackoff{results: []bool{true}}

	l := logger.NewWithoutConfig("")

	err := retryEnroll(cancelErr, 5, l, enrollFn, "http://localhost", fb)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, called, 0)
}
