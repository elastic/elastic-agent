// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package host

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/hostinfo"
	"github.com/elastic/elastic-agent/internal/pkg/util"
	testlogger "github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/go-sysinfo/types"
)

// startProvider runs a host provider with the given check interval, whose host information has the hostname
// returned by hostname, and calls onSet whenever it sets the mapping. It returns the comm the provider sets the
// mapping on, and a function that stops the provider and returns the error it returned.
func startProvider(t *testing.T, checkInterval time.Duration, hostname func() string, onSet func(map[string]interface{})) (*ctesting.ContextComm, func() error) {
	log, _ := testlogger.New(t.Name())
	c, err := config.NewConfigFrom(map[string]interface{}{
		"check_interval": checkInterval,
	})
	require.NoError(t, err)
	provider, err := ContextProviderBuilder(log, c, true)
	require.NoError(t, err)
	hostProvider, ok := provider.(*contextProvider)
	require.True(t, ok)
	require.Equal(t, checkInterval, hostProvider.CheckInterval)
	hostProvider.fetcher = func(context.Context) (hostinfo.Info, error) {
		return hostinfo.Info{Hostname: hostname()}, nil
	}

	ctx, cancel := context.WithCancel(t.Context())
	comm := ctesting.NewContextComm(ctx)
	if onSet != nil {
		comm.CallOnSet(onSet)
	}
	done := make(chan error)
	go func() { done <- provider.Run(ctx, comm) }()
	return comm, func() error {
		cancel()
		err := <-done
		require.NoError(t, hostProvider.Close())
		return err
	}
}

func TestContextProvider(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var hostname atomic.Value
		hostname.Store("Host-0")
		var sets atomic.Int32
		comm, stop := startProvider(t, time.Minute, func() string { return hostname.Load().(string) },
			func(map[string]interface{}) { sets.Add(1) })

		synctest.Wait()
		assert.Equal(t, "host-0", comm.Current()["name"])

		// The provider sets the mapping again once the host information changed and the check interval passed.
		hostname.Store("Host-1")
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, "host-1", comm.Current()["name"])

		// The mapping isn't set again if the host information doesn't change.
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		assert.ErrorIs(t, stop(), context.Canceled)
		assert.EqualValues(t, 2, sets.Load())
	})
}

func TestFQDNFeatureFlagToggle(t *testing.T) {
	setFQDN := func(enabled bool) {
		require.NoError(t, features.Apply(config.MustNewConfigFrom(map[string]interface{}{
			"agent.features.fqdn.enabled": enabled,
		})))
	}
	setFQDN(false)
	t.Cleanup(func() { setFQDN(false) })

	synctest.Test(t, func(t *testing.T) {
		var hostname atomic.Value
		hostname.Store("host")
		start := time.Now()
		// Use a long check interval so we can ensure that the host information isn't fetched again due to the
		// interval timer elapsing.
		comm, stop := startProvider(t, 10*time.Minute, func() string { return hostname.Load().(string) }, nil)
		synctest.Wait()
		assert.Equal(t, "host", comm.Current()["name"])

		// Toggling the FQDN feature flag fetches the host information again.
		hostname.Store("host.example.com")
		setFQDN(true)
		synctest.Wait()
		assert.Equal(t, "host.example.com", comm.Current()["name"])
		assert.Zero(t, time.Since(start))
		assert.ErrorIs(t, stop(), context.Canceled)
	})
}

func TestContextProviderInitialFetchFails(t *testing.T) {
	log, _ := testlogger.New(t.Name())
	provider, err := ContextProviderBuilder(log, nil, true)
	require.NoError(t, err)
	fetchErr := errors.New("fetch failed")
	provider.(*contextProvider).fetcher = func(context.Context) (hostinfo.Info, error) {
		return hostinfo.Info{}, fetchErr
	}

	err = provider.Run(t.Context(), ctesting.NewContextComm(t.Context()))
	assert.ErrorIs(t, err, fetchErr)
}

func TestHostMapping(t *testing.T) {
	info := hostinfo.Info{
		Hostname:     "My-Host.Example.com",
		ID:           "host-id",
		Architecture: "x86_64",
		IPs:          []string{"10.0.0.1"},
		MACs:         []string{"00:00:00:00:00:01"},
		OS:           types.OSInfo{Family: "debian", Platform: "ubuntu", Version: "24.04"},
	}
	assert.Equal(t, map[string]interface{}{
		"id":           "host-id",
		"name":         "my-host.example.com",
		"platform":     runtime.GOOS,
		"architecture": "x86_64",
		"ip":           []string{"10.0.0.1"},
		"mac":          []string{"00:00:00:00:00:01"},
		"os_family":    "debian",
		"os_platform":  "ubuntu",
		"os_version":   "24.04",
	}, hostMapping(info))
}

func TestHostMappingLowercasesHostnameOverride(t *testing.T) {
	// Unlike add_host_metadata in Beats, the provider lowercases ELASTIC_AGENT_HOSTNAME, see the hostinfo package
	// documentation.
	t.Setenv(util.EnvHostName, "My-Node")
	l, _ := testlogger.New(t.Name())
	info, err := hostinfo.Fetch(l)
	require.NoError(t, err)
	assert.Equal(t, "my-node", hostMapping(info)["name"])
}
