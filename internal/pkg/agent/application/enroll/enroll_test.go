// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package enroll

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// fakeBackoff allows controlling the sequence of Wait() return values for tests.
type fakeBackoff struct {
	results []bool
	block   chan struct{}
}

// Wait returns values from results (FIFO), or true when results is empty.
// If block is non-nil, it simulates an infinite backoff.
func (f *fakeBackoff) Wait() bool {
	if f.block != nil {
		<-f.block
	}
	if len(f.results) > 0 {
		r := f.results[0]
		f.results = f.results[1:]
		return r
	}
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

	fb := &fakeBackoff{}

	l := logger.NewWithoutConfig("")

	err := retryEnroll(t.Context(), initialErr, 5, l, enrollFn, "http://localhost", fb)
	require.NoError(t, err)
	require.Equal(t, 1, called)
}

func TestRetryEnroll_StopsAfterMaxAttempts(t *testing.T) {
	initialErr := fmt.Errorf("network")
	called := 0
	maxAttempts := 5
	enrollFn := func() error {
		called++
		return errors.New("still failing")
	}

	fb := &fakeBackoff{}

	l := logger.NewWithoutConfig("")

	err := retryEnroll(t.Context(), initialErr, maxAttempts, l, enrollFn, "http://localhost", fb)
	require.Equal(t, maxAttempts-1, called)
	require.Error(t, err)                  // error is expected
	require.NotErrorIs(t, err, initialErr) // subsequent failures are different
}

func TestRetryEnroll_ExitsOnBackoffStop(t *testing.T) {
	initialErr := fmt.Errorf("initial")
	called := 0
	enrollFn := func() error {
		called++
		return errors.New("still failing")
	}

	fb := &fakeBackoff{results: []bool{false}}

	l := logger.NewWithoutConfig("")

	err := retryEnroll(t.Context(), initialErr, -1, l, enrollFn, "http://localhost", fb)
	require.Equal(t, 0, called)
	require.ErrorIs(t, err, initialErr) // error is expected
}

func TestRetryEnroll_ExitsOnTerminalEnrollError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"context canceled", context.Canceled},
		{"deadline exceeded", context.DeadlineExceeded},
		{"invalid token", fleetapi.ErrInvalidToken},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := 0
			enrollFn := func() error {
				called++
				return nil
			}
			fb := &fakeBackoff{}
			l := logger.NewWithoutConfig("")

			err := retryEnroll(t.Context(), tc.err, 5, l, enrollFn, "http://localhost", fb)
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, 0, called)
		})
	}
}

func TestRetryEnroll_InterruptsBackoffWaitOnCtxCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		fb := &fakeBackoff{block: make(chan struct{})}
		defer close(fb.block)

		enrollFn := func() error { return errors.New("still failing") }

		l := logger.NewWithoutConfig("")

		errCh := make(chan error, 1)
		go func() {
			errCh <- retryEnroll(ctx, errors.New("initial"), -1, l, enrollFn, "http://localhost", fb)
		}()

		// retryEnroll should return when the caller's context is canceled, even if the retry
		// loop is currently blocked in backoff.Wait()
		synctest.Wait()
		cancel()

		err := <-errCh
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestLoadPersistentConfig_FleetCheckin(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected *configuration.FleetCheckin
	}{
		{
			name:     "no fleet.checkin uses default",
			yaml:     "",
			expected: configuration.DefaultFleetCheckin(),
		},
		{
			name: "compression none",
			yaml: "fleet:\n  checkin:\n    compression: none\n",
			expected: &configuration.FleetCheckin{
				Compression: configuration.CheckinCompressionNone,
			},
		},
		{
			name: "compression gzip",
			yaml: "fleet:\n  checkin:\n    compression: gzip\n",
			expected: &configuration.FleetCheckin{
				Compression: configuration.CheckinCompressionGzip,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp(t.TempDir(), "elastic-agent-*.yml")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(tmpFile.Name(), []byte(tc.yaml), 0o600))
			tmpFile.Close()

			result, err := LoadPersistentConfig(tmpFile.Name())
			require.NoError(t, err)

			require.Contains(t, result, "fleet.checkin")
			require.Equal(t, tc.expected, result["fleet.checkin"])
		})
	}
}
