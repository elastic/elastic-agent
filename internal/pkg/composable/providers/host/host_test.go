// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package host

import (
	"context"
	"net"
	"os"

	"github.com/elastic/elastic-agent/pkg/features"

	"github.com/foxcpp/go-mockdns"

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
	fetcher := getHostInfo(log)
	starting, err := fetcher()
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
	next, err := fetcher()
	require.NoError(t, err)
	next["idx"] = 1
	next, err = ctesting.CloneMap(next)
	require.NoError(t, err)
	assert.Equal(t, next, comm.Current())
}

func TestGetHostInfo(t *testing.T) {
	log, err := logger.New("host_test", false)
	require.NoError(t, err)

	fetcher := getHostInfo(log)

	hostname, err := os.Hostname()
	require.NoError(t, err)

	tests := map[string]struct {
		cnameLookupResult string
		expectedHostName  string
	}{
		"lookup_succeeds": {
			cnameLookupResult: "foo.bar.baz.",
			expectedHostName:  "foo.bar.baz",
		},
		"lookup_fails": {
			cnameLookupResult: "",
			expectedHostName:  hostname,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Mock CNAME resolution
			srv, _ := mockdns.NewServer(map[string]mockdns.Zone{
				hostname + ".": {
					CNAME: test.cnameLookupResult,
				},
				test.cnameLookupResult: {
					A: []string{"1.1.1.1"},
				},
			}, true)
			defer srv.Close()

			srv.PatchNet(net.DefaultResolver)
			defer mockdns.UnpatchNet(net.DefaultResolver)

			// Enable FQDN feature flag
			err = features.Apply(fqdnFeatureFlagConfig(true))
			require.NoError(t, err)
			defer func() {
				err = features.Apply(fqdnFeatureFlagConfig(true))
				require.NoError(t, err)
			}()

			info, err := fetcher()
			require.NoError(t, err)

			require.Equal(t, test.expectedHostName, info["name"])
		})
	}
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

func fqdnFeatureFlagConfig(fqdnEnabled bool) *config.Config {
	return config.MustNewConfigFrom(map[string]interface{}{
		"agent.features.fqdn.enabled": fqdnEnabled,
	})
}
