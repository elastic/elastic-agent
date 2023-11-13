// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package host

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/composable"
	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
)

func TestContextProvider(t *testing.T) {
	log, err := logger.New("host_test", false)
	require.NoError(t, err)

	// first call will have idx of 0
	fetcher := getHostInfo(log)
	starting, err := fetcher()
	starting["idx"] = 0
	require.NoError(t, err)

	const checkInterval = 50 * time.Millisecond
	const testTimeout = 1 * time.Second
	c, err := config.NewConfigFrom(map[string]interface{}{
		"check_interval": checkInterval,
	})
	require.NoError(t, err)
	builder, _ := composable.Providers.GetContextProvider("host")
	provider, err := builder(log, c, true)
	require.NoError(t, err)

	hostProvider, _ := provider.(*contextProvider)
	// returnHostMapping is a wrapper around getHostInfo that adds an
	// idx field to the returned values, incremented each time it is
	// invoked, starting from 0 on the first call.
	hostProvider.fetcher = returnHostMapping(log)
	require.Equal(t, checkInterval, hostProvider.CheckInterval)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := ctesting.NewContextComm(ctx)
	setChan := make(chan map[string]interface{})
	comm.CallOnSet(func(value map[string]interface{}) {
		// Forward Set's input to the test channel
		setChan <- value
	})

	go func() {
		_ = provider.Run(ctx, comm)
	}()

	// wait for it to be called once
	var current map[string]interface{}
	select {
	case current = <-setChan:
	case <-time.After(testTimeout):
		require.FailNow(t, "timeout waiting for provider to call Set")
	}

	starting, err = ctesting.CloneMap(starting)
	require.NoError(t, err)
	require.Equal(t, starting, current)

	// wait for it to be called again
	select {
	case current = <-setChan:
	case <-time.After(testTimeout):
		require.FailNow(t, "timeout waiting for provider to call Set")
	}
	cancel()

	// next should have been set idx to 1
	next, err := fetcher()
	require.NoError(t, err)
	next["idx"] = 1
	next, err = ctesting.CloneMap(next)
	require.NoError(t, err)
	assert.Equal(t, next, current)
}

func TestFQDNFeatureFlagToggle(t *testing.T) {
	log, err := logger.New("host_test", false)
	require.NoError(t, err)

	c, err := config.NewConfigFrom(map[string]interface{}{
		// Use a long check interval so we can ensure that any
		// calls to hostProvider.fetcher are not happening due
		// to the interval timer elapsing. We want such calls
		// to happen only due to explicit actions in our
		// test below.
		"check_interval": 10 * time.Minute,
	})
	require.NoError(t, err)

	builder, _ := composable.Providers.GetContextProvider("host")
	provider, err := builder(log, c, true)
	require.NoError(t, err)

	hostProvider, ok := provider.(*contextProvider)
	require.True(t, ok)
	defer func() {
		err := hostProvider.Close()
		require.NoError(t, err)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := ctesting.NewContextComm(ctx)

	calledChan := make(chan struct{})
	const expectedCalledCount = 2
	// Send to calledChan when called, so we can detect the number
	// of calls below.
	hostProvider.fetcher = func() (map[string]interface{}, error) {
		calledChan <- struct{}{}
		return nil, nil
	}

	// Run the provider
	go func() {
		err = hostProvider.Run(ctx, comm)
	}()

	// Trigger the FQDN feature flag callback by
	// toggling the FQDN feature flag
	err = features.Apply(config.MustNewConfigFrom(map[string]interface{}{
		"agent.features.fqdn.enabled": true,
	}))
	require.NoError(t, err)

	timeoutChan := time.After(100 * time.Millisecond)
	calledCount := 0
waitLoop:
	// Wait until we get the expected number of calls or the timeout
	// expires, whichever comes first.
	for calledCount < expectedCalledCount {
		select {
		case <-calledChan:
			calledCount++
		case <-timeoutChan:
			break waitLoop
		}
	}
	require.Equal(t, expectedCalledCount, calledCount)
}

func returnHostMapping(log *logger.Logger) infoFetcher {
	i := -1
	fetcher := getHostInfo(log)
	return func() (map[string]interface{}, error) {
		host, err := fetcher()
		if err != nil {
			return nil, err
		}
		i++
		host["idx"] = i
		return host, nil
	}
}
