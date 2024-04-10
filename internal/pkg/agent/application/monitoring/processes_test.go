// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

type mockCoordinator struct {
	state coordinator.State
	isUp  bool
}

func (mc mockCoordinator) State() coordinator.State {
	return mc.state
}

func (mc mockCoordinator) CoordinatorActive(_ time.Duration) bool {
	return mc.isUp
}

type mockContext struct {
	parent context.Context
	vars   map[string]string
}

func (mc mockContext) Deadline() (deadline time.Time, ok bool) {
	return mc.parent.Deadline()
}

func (mc mockContext) Done() <-chan struct{} {
	return mc.parent.Done()
}

func (mc mockContext) Err() error {
	return mc.parent.Err()
}

func (mc mockContext) Value(key any) any {
	// the gorilla mux uses a private type wrapper for the key, so we just gotta blindly return a map if we want this to work in a test
	return mc.vars
}

func TestProcessHTTPHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testCases := []struct {
		name         string
		coord        mockCoordinator
		expectedCode int
		liveness     bool
		failon       string
	}{
		{
			name: "degraded",
			coord: mockCoordinator{
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
			},
			expectedCode: 500,
			liveness:     true,
			failon:       "degraded",
		},
		{
			name: "degraded-check-off",
			coord: mockCoordinator{
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
			},
			expectedCode: 200,
			liveness:     true,
			failon:       "failed",
		},
		{
			name: "degraded-liveness-off",
			coord: mockCoordinator{
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
			},
			expectedCode: 200,
			liveness:     false,
			failon:       "degraded",
		},
		{
			name: "healthy",
			coord: mockCoordinator{
				isUp: true,
				state: coordinator.State{
					Components: []runtime.ComponentComponentState{
						{
							LegacyPID: "5",
							State:     runtime.ComponentState{State: client.UnitStateHealthy},
							Component: component.Component{
								ID: "test-component3",
								InputSpec: &component.InputRuntimeSpec{
									BinaryName: "testbeat",
								},
							},
						},
					},
				},
			},
			expectedCode: 200,
			liveness:     true,
			failon:       "degraded",
		},
		{
			name: "healthy-coordinator-down",
			coord: mockCoordinator{
				isUp: false,
				state: coordinator.State{
					Components: []runtime.ComponentComponentState{
						{
							LegacyPID: "5",
							State:     runtime.ComponentState{State: client.UnitStateHealthy},
							Component: component.Component{
								ID: "test-component3",
								InputSpec: &component.InputRuntimeSpec{
									BinaryName: "testbeat",
								},
							},
						},
					},
				},
			},
			expectedCode: 500,
			liveness:     true,
			failon:       "degraded",
		},
		{
			name: "healthy-liveness-off",
			coord: mockCoordinator{
				isUp: true,
				state: coordinator.State{
					Components: []runtime.ComponentComponentState{
						{
							LegacyPID: "5",
							State:     runtime.ComponentState{State: client.UnitStateHealthy},
							Component: component.Component{
								ID: "test-component3",
								InputSpec: &component.InputRuntimeSpec{
									BinaryName: "testbeat",
								},
							},
						},
					},
				},
			},
			expectedCode: 200,
			liveness:     false,
			failon:       "degraded",
		},
		{
			name: "degraded-and-healthy",
			coord: mockCoordinator{
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
						{
							LegacyPID: "3",
							State:     runtime.ComponentState{State: client.UnitStateHealthy},
							Component: component.Component{
								ID: "test-component2",
								InputSpec: &component.InputRuntimeSpec{
									BinaryName: "testbeat",
								},
							},
						},
					},
				},
			},
			expectedCode: 500,
			liveness:     true,
			failon:       "degraded",
		},
	}

	// test with processesHandler
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			testSrv := httptest.NewServer(createHandler(processesHandler(test.coord, test.liveness)))
			defer testSrv.Close()

			path := fmt.Sprintf("%s?failon=%s", testSrv.URL, test.failon)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
			require.NoError(t, err)
			res, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			res.Body.Close()

		})
	}

	// test with processHandler
	for _, test := range testCases {
		t.Run(fmt.Sprintf("process-%s", test.name), func(t *testing.T) {
			testSrv := httptest.NewUnstartedServer(createHandler(processHandler(test.coord, test.liveness, nil)))
			defer testSrv.Close()

			customContext := func(ctx context.Context, c net.Conn) context.Context {
				return mockContext{parent: ctx, vars: map[string]string{componentIDKey: test.coord.state.Components[0].Component.ID}}
			}
			testSrv.Config.ConnContext = customContext
			testSrv.Start()

			path := fmt.Sprintf("%s?failon=%s", testSrv.URL, test.failon)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
			require.NoError(t, err)
			res, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			res.Body.Close()

			require.Equal(t, test.expectedCode, res.StatusCode)
		})
	}

}
