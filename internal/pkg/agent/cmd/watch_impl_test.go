// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func Test_watchLoop(t *testing.T) {

	t.Run("watchloop returns when context expires - no error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		log, _ := loggertest.New(t.Name())
		signals := make(chan os.Signal, 1)
		errChan := make(chan error, 1)
		graceTimer := make(chan time.Time, 1)
		err := watchLoop(ctx, log, signals, errChan, graceTimer)
		require.NoError(t, err)
	})

	t.Run("watchloop returns when grace timer triggers - no error", func(t *testing.T) {
		log, _ := loggertest.New(t.Name())
		signals := make(chan os.Signal, 1)
		errChan := make(chan error, 1)
		graceTimer := make(chan time.Time, 1)
		graceTimer <- time.Now()
		err := watchLoop(t.Context(), log, signals, errChan, graceTimer)
		require.NoError(t, err)
	})

	t.Run("watchloop returns when error from AgentWatcher is received - error", func(t *testing.T) {
		log, _ := loggertest.New(t.Name())
		signals := make(chan os.Signal, 1)
		errChan := make(chan error, 1)
		graceTimer := make(chan time.Time, 1)
		agentWatcherError := fmt.Errorf("some error")
		errChan <- agentWatcherError
		err := watchLoop(t.Context(), log, signals, errChan, graceTimer)
		require.ErrorIs(t, err, agentWatcherError)
	})

	t.Run("watchloop returns when receiving signals - error", func(t *testing.T) {
		testSignals := []syscall.Signal{
			syscall.SIGTERM,
			syscall.SIGINT,
		}

		for _, signal := range testSignals {
			t.Run(signal.String(), func(t *testing.T) {
				log, _ := loggertest.New(t.Name())
				signals := make(chan os.Signal, 1)
				errChan := make(chan error, 1)
				graceTimer := make(chan time.Time, 1)
				signals <- signal
				err := watchLoop(t.Context(), log, signals, errChan, graceTimer)
				assert.ErrorIs(t, err, ErrWatchCancelled)
			})
		}
	})
}
