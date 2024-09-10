// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package util

import (
	"context"
	"errors"
	"testing"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/stretchr/testify/require"

	"github.com/elastic/go-sysinfo/types"
)

func TestGetHostName(t *testing.T) {
	cases := map[string]struct {
		fqdnFeatureEnabled bool
		hostInfo           types.HostInfo
		host               types.Host
		log                *logp.Logger

		expected string
	}{
		"fqdn_feature_disabled": {
			fqdnFeatureEnabled: false,
			hostInfo:           types.HostInfo{Hostname: "foobar"},
			expected:           "foobar",
		},
		"fqdn_lookup_fails": {
			fqdnFeatureEnabled: true,
			hostInfo:           types.HostInfo{Hostname: "foobar"},
			host: &mockHost{
				fqdn:    "",
				fqdnErr: errors.New("fqdn lookup failed while testing"),
			},
			log:      logp.NewLogger("testing"),
			expected: "foobar",
		},
		"fqdn_lookup_succeeds": {
			fqdnFeatureEnabled: true,
			hostInfo:           types.HostInfo{Hostname: "foobar"},
			host: &mockHost{
				fqdn:    "qux",
				fqdnErr: nil,
			},
			expected: "qux",
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			hostname := GetHostName(test.fqdnFeatureEnabled, test.hostInfo, test.host, test.log)
			require.Equal(t, test.expected, hostname)
		})
	}
}

type mockHost struct {
	fqdn    string
	fqdnErr error
}

func (m *mockHost) CPUTime() (types.CPUTimes, error)       { return types.CPUTimes{}, nil }
func (m *mockHost) Info() types.HostInfo                   { return types.HostInfo{} }
func (m *mockHost) Memory() (*types.HostMemoryInfo, error) { return nil, nil }
func (m *mockHost) FQDNWithContext(ctx context.Context) (string, error) {
	return m.fqdn, m.fqdnErr
}
func (m *mockHost) FQDN() (string, error) { return m.FQDNWithContext(context.Background()) }
