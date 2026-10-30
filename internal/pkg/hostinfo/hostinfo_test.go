// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package hostinfo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/go-sysinfo/types"

	"github.com/elastic/elastic-agent/internal/pkg/util"
	testlogger "github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestFromHost(t *testing.T) {
	t.Setenv(util.EnvHostName, "")
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
		fqdn: "FooBar.Example.com",
	}

	expected := Info{
		Hostname:      "FooBar",
		ID:            "host-id",
		Architecture:  "x86_64",
		KernelVersion: "6.1.0",
		IPs:           []string{"10.0.0.1"},
		MACs:          []string{"00:00:00:00:00:01"},
		OS:            types.OSInfo{Family: "debian", Platform: "ubuntu", Name: "Ubuntu", Version: "24.04"},
	}
	info := fromHost(host, false, log)
	require.Equal(t, expected, info)
	require.Equal(t, "foobar", info.Name())

	expected.Hostname = "FooBar.Example.com"
	require.Equal(t, expected, fromHost(host, true, log), "the FQDN is used when the feature is enabled")

}

type mockHost struct {
	info    types.HostInfo
	fqdn    string
	fqdnErr error
}

func (m *mockHost) CPUTime() (types.CPUTimes, error)       { return types.CPUTimes{}, nil }
func (m *mockHost) Info() types.HostInfo                   { return m.info }
func (m *mockHost) Memory() (*types.HostMemoryInfo, error) { return nil, nil }
func (m *mockHost) FQDNWithContext(ctx context.Context) (string, error) {
	return m.fqdn, m.fqdnErr
}
func (m *mockHost) FQDN() (string, error) { return m.FQDNWithContext(context.Background()) }
