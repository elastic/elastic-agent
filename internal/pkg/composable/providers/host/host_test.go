// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package host

import (
	"context"

	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/composable"
	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestContextProvider(t *testing.T) {
	log, err := logger.New("host_test", false)
	require.NoError(t, err)

	// first call will have idx of 0
	starting, err := getHostInfo(log)
	starting["idx"] = 0
	require.NoError(t, err)

	c, err := config.NewConfigFrom(map[string]interface{}{
		"check_interval": 100 * time.Millisecond,
	})
	require.NoError(t, err)
	builder, _ := composable.Providers.GetContextProvider("host")
	provider, err := builder(log, c, true)
	require.NoError(t, err)

	hostProvider, _ := provider.(*contextProvider)
	hostProvider.fetcher = returnHostMapping(log)
	require.Equal(t, 100*time.Millisecond, hostProvider.CheckInterval)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := ctesting.NewContextComm(ctx)

	go func() {
		err = provider.Run(comm)
	}()

	// wait for it to be called once
	var wg sync.WaitGroup
	wg.Add(1)
	comm.CallOnSet(func() {
		wg.Done()
	})
	wg.Wait()
	comm.CallOnSet(nil)

	require.NoError(t, err)
	starting, err = ctesting.CloneMap(starting)
	require.NoError(t, err)
	require.Equal(t, starting, comm.Current())

	// wait for it to be called again
	wg.Add(1)
	comm.CallOnSet(func() {
		wg.Done()
	})
	wg.Wait()
	comm.CallOnSet(nil)
	cancel()

	// next should have been set idx to 1
	next, err := getHostInfo(log)
	require.NoError(t, err)
	next["idx"] = 1
	next, err = ctesting.CloneMap(next)
	require.NoError(t, err)
	assert.Equal(t, next, comm.Current())
}

func returnHostMapping(log *logger.Logger) infoFetcher {
	i := -1
	return func() (map[string]interface{}, error) {
		host, err := getHostInfo(log)
		if err != nil {
			return nil, err
		}
		i++
		host["idx"] = i
		return host, nil
	}
}
