// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
)

func TestCoordinatorWithErrors(t *testing.T) {
	handlerChan, runtime, varWatcher, config := setupAndWaitCoordinatorDone()

	close(runtime)
	close(varWatcher)
	cfgErrStr := "configWatcher error"
	config <- errors.New(cfgErrStr)

	// All the multierror stuff breaks errors.Is
	waitAndTestError(t, func(err error) bool { return strings.Contains(err.Error(), cfgErrStr) }, handlerChan)

}

func TestCoordinatorShutdownClosedChannels(t *testing.T) {
	CoordinatorShutdownTimeout = time.Second * 5
	handlerChan, runtime, varWatcher, config := setupAndWaitCoordinatorDone()

	close(runtime)
	close(varWatcher)
	close(config)

	waitAndTestError(t, func(err error) bool { return errors.Is(err, context.Canceled) }, handlerChan)

}

func TestCoordinatorShutdownTimeout(t *testing.T) {
	CoordinatorShutdownTimeout = time.Millisecond
	handlerChan, _, _, _ := setupAndWaitCoordinatorDone()
	waitAndTestError(t, func(err error) bool { return errors.Is(err, context.Canceled) }, handlerChan)
}

func TestCoordinatorShutdownErrorWithClose(t *testing.T) {
	CoordinatorShutdownTimeout = time.Second * 5
	handlerChan, runtime, varWatcher, config := setupAndWaitCoordinatorDone()
	// return an error, then close the channel
	cfgErrStr := "config watcher error"
	config <- errors.New(cfgErrStr)
	close(config)

	close(runtime)
	close(varWatcher)

	waitAndTestError(t, func(err error) bool { return strings.Contains(err.Error(), cfgErrStr) }, handlerChan)
}

func TestCoordinatorShutdownErrorWithoutClose(t *testing.T) {
	CoordinatorShutdownTimeout = time.Millisecond
	handlerChan, _, _, config := setupAndWaitCoordinatorDone()

	cfgErrStr := "config watcher error"
	config <- errors.New(cfgErrStr)

	waitAndTestError(t, func(err error) bool { return strings.Contains(err.Error(), cfgErrStr) }, handlerChan)
}

func TestCoordinatorShutdownErrorCloseTimeout(t *testing.T) {
	CoordinatorShutdownTimeout = time.Second
	handlerChan, _, varWatcher, config := setupAndWaitCoordinatorDone()
	// return an error on one chanel, close another, let another time out
	cfgErrStr := "config watcher error"
	config <- errors.New(cfgErrStr)

	close(varWatcher)

	waitAndTestError(t, func(err error) bool { return strings.Contains(err.Error(), cfgErrStr) }, handlerChan)
}

func waitAndTestError(t *testing.T, check func(error) bool, handlerErr chan error) {
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second*4)
	defer waitCancel()
	for {
		select {
		case <-waitCtx.Done():
			t.Fatalf("handleCoordinatorDone timed out while waiting for shutdown")
		case gotErr := <-handlerErr:
			if handlerErr != nil {
				if check(gotErr) {
					t.Logf("got correct error")
					return
				} else {
					t.Fatalf("got incorrect error: %s", gotErr)
				}
			}
		}

	}
}

func setupAndWaitCoordinatorDone() (chan error, chan error, chan error, chan error) {
	runtime := make(chan error)
	varWatcher := make(chan error)
	config := make(chan error)

	testCord := Coordinator{logger: logp.L()}

	ctx, cancel := context.WithCancel(context.Background())
	// emulate shutdown
	cancel()

	handlerChan := make(chan error)
	go func() {
		handlerErr := testCord.handleCoordinatorDone(ctx, varWatcher, runtime, config)
		handlerChan <- handlerErr
	}()

	return handlerChan, runtime, varWatcher, config
}
