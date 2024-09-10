// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/api"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/reload"
	aConfig "github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

var fakeCoordCfg = mockCoordinator{
	isUp: true,
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

func TestHTTPReloadEnableBehavior(t *testing.T) {
	// see https://github.com/elastic/elastic-agent/issues/4582
	// This tests how the reloader behaves depending on what config values are set.
	type reloadCase struct {
		name              string
		initConfig        *config.MonitoringConfig
		secondConfig      *aConfig.Config
		httpOnAtInit      bool
		httpOnAfterReload bool
	}

	cases := []reloadCase{
		{
			name:       "enabled-with-reload-empty",
			initConfig: &config.MonitoringConfig{Enabled: true, HTTP: &config.MonitoringHTTPConfig{Enabled: true}},
			// use a map so we can specify port 0 with out setting `enabled`
			secondConfig: aConfig.MustNewConfigFrom(map[string]interface{}{"agent": map[string]interface{}{
				"monitoring": map[string]interface{}{"enabled": true, "http": map[string]interface{}{"port": 0}}}}),
			httpOnAtInit:      true,
			httpOnAfterReload: true,
		},
		{
			name:       "disabled-with-reload-empty",
			initConfig: &config.MonitoringConfig{Enabled: true, HTTP: &config.MonitoringHTTPConfig{Enabled: false}},
			secondConfig: aConfig.MustNewConfigFrom(map[string]interface{}{"agent": map[string]interface{}{
				"monitoring": map[string]interface{}{"enabled": true, "http": map[string]interface{}{"port": 0}}}}),
			httpOnAtInit:      false,
			httpOnAfterReload: false,
		},
		{
			name:       "disabled-with-reload-disabled",
			initConfig: &config.MonitoringConfig{Enabled: true, HTTP: &config.MonitoringHTTPConfig{Enabled: false}},
			secondConfig: aConfig.MustNewConfigFrom(map[string]interface{}{"agent": map[string]interface{}{
				"monitoring": map[string]interface{}{"enabled": true, "http": map[string]interface{}{"port": 0, "enabled": false}}}}),
			httpOnAtInit:      false,
			httpOnAfterReload: false,
		},
		{
			name:       "enabled-with-reload-disabled",
			initConfig: &config.MonitoringConfig{Enabled: true, HTTP: &config.MonitoringHTTPConfig{Enabled: true}},
			secondConfig: aConfig.MustNewConfigFrom(map[string]interface{}{"agent": map[string]interface{}{
				"monitoring": map[string]interface{}{"enabled": true, "http": map[string]interface{}{"port": 0, "enabled": false}}}}),
			httpOnAtInit:      true,
			httpOnAfterReload: false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			serverReloader, err := NewServer(logp.L(), api.Config{}, nil, nil, fakeCoordCfg, "linux", testCase.initConfig)
			require.NoError(t, err)

			t.Logf("starting server...")
			serverReloader.Start()
			if testCase.httpOnAtInit {
				waitOnReturnCode(t, http.StatusOK, "?failon=failed", serverReloader)
			} else {
				waitOnReturnCode(t, http.StatusNotFound, "?failon=failed", serverReloader)
			}

			err = serverReloader.Reload(testCase.secondConfig)
			require.NoError(t, err)

			if testCase.httpOnAfterReload {
				waitOnReturnCode(t, http.StatusOK, "?failon=failed", serverReloader)
			} else {
				waitOnReturnCode(t, http.StatusNotFound, "?failon=failed", serverReloader)
			}

		})
	}
}

func TestBasicLivenessConfig(t *testing.T) {
	_ = logp.DevelopmentSetup()
	testAPIConfig := api.Config{}
	testConfig := config.MonitoringConfig{
		Enabled: true,
		HTTP: &config.MonitoringHTTPConfig{
			Enabled: true,
			Port:    0,
		},
	}
	serverReloader, err := NewServer(logp.L(), testAPIConfig, nil, nil, fakeCoordCfg, "linux", &testConfig)
	require.NoError(t, err)

	t.Logf("starting server...")
	serverReloader.Start()

	waitOnReturnCode(t, http.StatusInternalServerError, "?failon=degraded", serverReloader)

	waitOnReturnCode(t, http.StatusOK, "?failon=failed", serverReloader)

	t.Logf("stopping server...")
	err = serverReloader.Stop()
	require.NoError(t, err)

}

func waitOnReturnCode(t *testing.T, expectedReturnCode int, formValue string, rel *reload.ServerReloader) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	client := &http.Client{}
	fastEventually(t, func() bool {
		path := fmt.Sprintf("http://%s/liveness%s", rel.Addr().String(), formValue)
		t.Logf("checking %s", path)
		req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		if err != nil {
			t.Logf("error fetching endpoint: %s", err)
			return false
		}
		defer resp.Body.Close()
		// should return 500 as we have one component set to UnitStateDegraded
		return resp.StatusCode == expectedReturnCode
	}, time.Second*30, time.Second*3)
}

func fastEventually(t *testing.T, condition func() bool, waitFor time.Duration, tick time.Duration) {
	if condition() {
		return
	}

	require.Eventually(t, condition, waitFor, tick)
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
