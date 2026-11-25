// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package hostinfo

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/go-sysinfo/types"

	testlogger "github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestOverride(t *testing.T) {
	cases := []struct {
		name     string
		envValue string
		expected string
	}{
		{name: "plain", envValue: "my-node", expected: "my-node"},
		{name: "leading_trailing_whitespace", envValue: "  my-node  ", expected: "my-node"},
		{name: "whitespace_only", envValue: "   ", expected: ""},
		{name: "unset", envValue: "", expected: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvOverride, tc.envValue)
			require.Equal(t, tc.expected, Override())
		})
	}
}

func TestLookupHostnameEnvOverride(t *testing.T) {
	cases := []struct {
		name     string
		envValue string
		expected string
	}{
		{name: "plain", envValue: "my-node", expected: "my-node"},
		{name: "trimmed", envValue: "  my-node  ", expected: "my-node"},
		{name: "case_preserved", envValue: "My-Node", expected: "My-Node"},
		{name: "whitespace_only", envValue: "   ", expected: "Pod-XYZ"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvOverride, tc.envValue)
			hostname := lookupHostname(t.Context(), types.HostInfo{Hostname: "Pod-XYZ"}, nil, false, nil)
			require.Equal(t, tc.expected, hostname)
		})
	}
}

func TestLookupHostname(t *testing.T) {
	t.Setenv(EnvOverride, "")
	log, _ := testlogger.New(t.Name())
	cases := map[string]struct {
		useFQDN  bool
		hostInfo types.HostInfo
		host     types.Host

		expected string
	}{
		"fqdn_feature_disabled": {
			useFQDN:  false,
			hostInfo: types.HostInfo{Hostname: "FooBar"},
			expected: "FooBar",
		},
		"fqdn_lookup_fails": {
			useFQDN:  true,
			hostInfo: types.HostInfo{Hostname: "FooBar"},
			host: &mockHost{
				fqdnErr: errors.New("fqdn lookup failed while testing"),
			},
			expected: "FooBar",
		},
		"fqdn_lookup_succeeds": {
			useFQDN:  true,
			hostInfo: types.HostInfo{Hostname: "FooBar"},
			host: &mockHost{
				fqdn: "Qux.Example.com",
			},
			expected: "Qux.Example.com",
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			hostname := lookupHostname(t.Context(), test.hostInfo, test.host, test.useFQDN, log)
			require.Equal(t, test.expected, hostname)
		})
	}
}

func TestFromHost(t *testing.T) {
	t.Setenv(EnvOverride, "")
	log, _ := testlogger.New(t.Name())
	host := &mockHost{
		info: types.HostInfo{
			Hostname:      "FooBar",
			UniqueID:      "host-id",
			Architecture:  "x86_64",
			KernelVersion: "6.1.0",
			IPs:           []string{"10.0.0.1"},
			MACs:          []string{"00:00:00:00:00:01"},
			OS:            &types.OSInfo{Family: "debian", Platform: "ubuntu", Name: "Ubuntu", Version: "24.04"},
		},
		fqdn:   "FooBar.Example.com",
		memory: &types.HostMemoryInfo{Total: 1024},
	}

	expected := Info{
		Hostname:      "FooBar",
		ID:            "host-id",
		Architecture:  "x86_64",
		KernelVersion: "6.1.0",
		IPs:           []string{"10.0.0.1"},
		MACs:          []string{"00:00:00:00:00:01"},
		OS:            types.OSInfo{Family: "debian", Platform: "ubuntu", Name: "Ubuntu", Version: "24.04"},
		MemoryTotal:   1024,
	}
	info := fromHost(t.Context(), host, false, log)
	require.Equal(t, expected, info)
	require.Equal(t, "foobar", info.Name())

	expected.Hostname = "FooBar.Example.com"
	require.Equal(t, expected, fromHost(t.Context(), host, true, log), "the FQDN is used when the feature is enabled")

	t.Run("memory_unavailable", func(t *testing.T) {
		host := &mockHost{info: types.HostInfo{Hostname: "foobar"}, memoryErr: errors.New("not available")}
		info := fromHost(t.Context(), host, false, log)
		require.Equal(t, Info{Hostname: "foobar"}, info, "the host information is returned without the memory")
	})
}

type mockHost struct {
	info      types.HostInfo
	fqdn      string
	fqdnErr   error
	memory    *types.HostMemoryInfo
	memoryErr error
}

func (m *mockHost) CPUTime() (types.CPUTimes, error)       { return types.CPUTimes{}, nil }
func (m *mockHost) Info() types.HostInfo                   { return m.info }
func (m *mockHost) Memory() (*types.HostMemoryInfo, error) { return m.memory, m.memoryErr }
func (m *mockHost) FQDNWithContext(ctx context.Context) (string, error) {
	return m.fqdn, m.fqdnErr
}
func (m *mockHost) FQDN() (string, error) { return m.FQDNWithContext(context.Background()) }
