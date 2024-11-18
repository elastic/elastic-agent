// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"

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

func (mc mockCoordinator) IsActive(_ time.Duration) bool {
	return mc.isUp
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
			name: "default-failed",
			coord: mockCoordinator{
				isUp: true,
				state: coordinator.State{
					Components: []runtime.ComponentComponentState{
						{
							LegacyPID: "2",
							State:     runtime.ComponentState{State: client.UnitStateFailed},
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
			failon:       "heartbeat",
		},
		{
			name: "default-healthy",
			coord: mockCoordinator{
				isUp: true,
				state: coordinator.State{
					Components: []runtime.ComponentComponentState{
						{
							LegacyPID: "2",
							State:     runtime.ComponentState{State: client.UnitStateHealthy},
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
			failon:       "heartbeat",
		},
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
			name: "coord-fail-only-healthy",
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
			expectedCode: 503,
			liveness:     true,
			failon:       "heartbeat",
		},
		{
			name: "coord-fail-only-failed",
			coord: mockCoordinator{
				isUp: false,
				state: coordinator.State{
					Components: []runtime.ComponentComponentState{
						{
							LegacyPID: "5",
							State:     runtime.ComponentState{State: client.UnitStateFailed},
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
			expectedCode: 503,
			liveness:     true,
			failon:       "heartbeat",
		},
		{
			name: "degraded-coordinator-down",
			coord: mockCoordinator{
				isUp: false,
				state: coordinator.State{
					Components: []runtime.ComponentComponentState{
						{
							LegacyPID: "5",
							State:     runtime.ComponentState{State: client.UnitStateDegraded},
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
			expectedCode: 503,
			liveness:     true,
			failon:       "degraded",
		},
		{
			name: "unhealthy-coordinator-down",
			coord: mockCoordinator{
				isUp: false,
				state: coordinator.State{
					Components: []runtime.ComponentComponentState{
						{
							LegacyPID: "5",
							State:     runtime.ComponentState{State: client.UnitStateFailed},
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
			expectedCode: 503,
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
			expectedCode: 503,
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
		{
			name: "healthy-liveness-off-otel",
			coord: mockCoordinator{
				isUp: true,
				state: coordinator.State{
					OTelStatus: &status.AggregateStatus{
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							"test-component": &status.AggregateStatus{
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
							"test-component2": &status.AggregateStatus{
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
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
			name: "degraded-and-healthy-otel",
			coord: mockCoordinator{
				isUp: true,
				state: coordinator.State{
					OTelStatus: &status.AggregateStatus{
						Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							"test-component": &status.AggregateStatus{
								Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
							},
							"test-component2": &status.AggregateStatus{
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
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
			testSrv := httptest.NewServer(createHandler(livenessHandler(test.coord)))
			defer testSrv.Close()

			path := fmt.Sprintf("%s?failon=%s", testSrv.URL, test.failon)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
			require.NoError(t, err)
			res, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			res.Body.Close()

		})
	}

}
