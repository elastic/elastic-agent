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
}

func (mc mockCoordinator) State() coordinator.State {
	return mc.state
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

	testCases := []struct {
		name         string
		coord        mockCoordinator
		expectedCode int
		liveness     bool
	}{
		{
			name: "degraded",
			coord: mockCoordinator{
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
		},
		{
			name: "degraded-liveness-off",
			coord: mockCoordinator{
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
		},
		{
			name: "healthy",
			coord: mockCoordinator{
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
		},
		{
			name: "healthy-liveness-off",
			coord: mockCoordinator{
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
		},
		{
			name: "degraded-and-healthy",
			coord: mockCoordinator{
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
		},
	}

	// test with processesHandler
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			testSrv := httptest.NewServer(createHandler(processesHandler(test.coord, test.liveness)))
			defer testSrv.Close()

			res, err := http.Get(testSrv.URL)
			require.NoError(t, err)
			defer res.Body.Close()
			require.Equal(t, test.expectedCode, res.StatusCode)

		})
	}

	// test with processHandler
	for _, test := range testCases {
		t.Run(fmt.Sprintf("process-%s", test.name), func(t *testing.T) {
			testSrv := httptest.NewUnstartedServer(createHandler(processHandler(test.coord, test.liveness, nil, "linux")))
			defer testSrv.Close()

			customContext := func(ctx context.Context, c net.Conn) context.Context {
				return mockContext{parent: ctx, vars: map[string]string{componentIDKey: test.coord.state.Components[0].Component.ID}}
			}
			testSrv.Config.ConnContext = customContext
			testSrv.Start()

			res, err := http.Get(testSrv.URL)
			require.NoError(t, err)
			res.Body.Close()
			require.Equal(t, test.expectedCode, res.StatusCode)
		})
	}

}
