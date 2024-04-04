// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/api"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestConfigUpdateOnReload(t *testing.T) {
	_ = logp.DevelopmentSetup()
	testAPIConfig := api.Config{}
	mockCoord := mockCoordinator{
		state: coordinator.State{
			Components: []runtime.ComponentComponentState{
				{
					LegacyPID: "2",
					State:     runtime.ComponentState{State: client.UnitStateDegraded},
					Component: component.Component{
						ID: "test-component",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "testbeat",
						},
					},
				},
			},
		},
	}
	testConfig := config.MonitoringConfig{
		Enabled: true,
		HTTP: &config.MonitoringHTTPConfig{
			Enabled: true,
			Port:    0,
		},
	}
	serverReloader, err := NewServer(logp.L(), testAPIConfig, nil, nil, mockCoord, "linux", &testConfig)
	require.NoError(t, err)

	t.Logf("starting server...")
	serverReloader.Start()

	waitOnReturnCode(t, http.StatusInternalServerError, "?failon=degraded", serverReloader.Addr())

	waitOnReturnCode(t, http.StatusOK, "?failon=failed", serverReloader.Addr())

	t.Logf("stopping server...")
	serverReloader.Stop()

}

func waitOnReturnCode(t *testing.T, expectedReturnCode int, formValue string, addr net.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	client := &http.Client{}
	path := fmt.Sprintf("http://%s/liveness%s", addr.String(), formValue)
	t.Logf("checking %s", path)
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		resp, err := client.Do(req)
		if err != nil {
			t.Logf("error fetching endpoint: %s", err)
			return false
		}
		// should return 500 as we have one component set to UnitStateDegraded
		return resp.StatusCode == expectedReturnCode
	}, time.Second*30, time.Second*3)
}

func TestIsHTTPUrl(t *testing.T) {

	tests := []struct {
		name string
		s    string
		res  bool
	}{
		{
			name: "empty",
		},
		{
			name: "/",
			s:    "/",
		},
		{
			name: "relative",
			s:    "foo/bar",
		},
		{
			name: "absolute",
			s:    "/foo/bar",
		},
		{
			name: "file",
			s:    "file://foo/bar",
		},
		{
			name: "http",
			s:    "http://localhost:5691",
			res:  true,
		},
		{
			name: "https",
			s:    "https://localhost:5691",
			res:  true,
		},
		{
			name: "http space prefix",
			s:    " http://localhost:5691",
			res:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := isHttpUrl(tc.s)
			diff := cmp.Diff(tc.res, res)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}
