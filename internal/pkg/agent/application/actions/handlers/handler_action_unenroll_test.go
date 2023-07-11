// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/stretchr/testify/require"
)

func makeComponentState(name string, proxiedActions []string) runtime.ComponentComponentState {
	return runtime.ComponentComponentState{
		Component: component.Component{
			InputType: name,
			Units: []component.Unit{
				{
					Type:   client.UnitTypeInput,
					Config: &proto.UnitExpectedConfig{Type: name},
				},
			},
			InputSpec: &component.InputRuntimeSpec{
				Spec: component.InputSpec{
					Name:           name,
					ProxiedActions: proxiedActions,
				},
			},
		},
	}
}

type MockActionCoordinator struct {
	st               coordinator.State
	performedActions int
}

func (c *MockActionCoordinator) State() coordinator.State {
	return c.st
}

func (c *MockActionCoordinator) PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
	c.performedActions++
	return nil, nil
}

func (c *MockActionCoordinator) Clear() {
	c.performedActions = 0
}

type MockAcker struct {
	Acked []fleetapi.Action
}

func (m *MockAcker) Ack(_ context.Context, action fleetapi.Action) error {
	m.Acked = append(m.Acked, action)
	return nil
}

func (m *MockAcker) Commit(_ context.Context) error {
	return nil
}

func (m *MockAcker) Clear() {
	m.Acked = nil
}

func TestActionUnenrollHandler(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	log, _ := logger.New("", false)
	coord := &MockActionCoordinator{}
	acker := &MockAcker{}

	action := &fleetapi.ActionUnenroll{
		ActionID:   "c80e9219-70bf-43d3-b8cd-b5131a771751",
		ActionType: "UNENROLL",
	}
	goodSigned := &fleetapi.Signed{
		Data:      "eyJAdGltZXN0YW1wIjoiMjAyMy0wNS0yMlQxNzoxOToyOC40NjNaIiwiZXhwaXJhdGlvbiI6IjIwMjMtMDYtMjFUMTc6MTk6MjguNDYzWiIsImFnZW50cyI6WyI3ZjY0YWI2NC1hNmM0LTQ2ZTMtODIyYS0zODUxZGVkYTJmY2UiXSwiYWN0aW9uX2lkIjoiNGYwODQ2MGYtMDE0Yy00ZDllLWJmOGEtY2FhNjQyNzRhZGU0IiwidHlwZSI6IlVORU5ST0xMIiwidHJhY2VwYXJlbnQiOiIwMC1iOTBkYTlmOGNjNzdhODk0OTc0ZWIxZTIzMGNmNjc2Yy1lOTNlNzk4YTU4ODg2MDVhLTAxIn0=",
		Signature: "MEUCIAxxsi9ff1zyV0+4fsJLqbP8Qb83tedU5iIFldtxEzEfAiEA0KUsrL7q+Fv7z6Boux3dY2P4emGi71jsMGanIZ552bM=",
	}
	action.Signed = goodSigned

	ch := make(chan coordinator.ConfigChange, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case policyChange := <-ch:
				_ = policyChange.Ack()
			}
		}
	}()

	handler := NewUnenroll(log, coord, ch, nil, nil)

	getTamperProtectionFunc := func(enabled bool) func() bool {
		return func() bool {
			return enabled
		}
	}

	tests := []struct {
		name                 string
		st                   coordinator.State
		wantErr              error // Handler error
		wantPerformedActions int
		tamperProtectionFn   func() bool
	}{
		{
			name: "no running components",
		},
		{
			name: "endpoint no dispatch",
			st: func() coordinator.State {
				return coordinator.State{
					Components: []runtime.ComponentComponentState{
						makeComponentState("endpoint", nil),
					},
				}
			}(),
		},
		{
			name: "endpoint with UNENROLL, tamper protection feature flag disabled",
			st: func() coordinator.State {
				return coordinator.State{
					Components: []runtime.ComponentComponentState{
						makeComponentState("endpoint", []string{"UNENROLL"}),
						makeComponentState("osquery", nil),
					},
				}
			}(),
			wantPerformedActions: 0,
		},
		{
			name: "endpoint with UNENROLL, tamper protection feature flag enabled",
			st: func() coordinator.State {
				return coordinator.State{
					Components: []runtime.ComponentComponentState{
						makeComponentState("endpoint", []string{"UNENROLL"}),
						makeComponentState("osquery", nil),
					},
				}
			}(),
			tamperProtectionFn:   getTamperProtectionFunc(true),
			wantPerformedActions: 1,
		},
		{
			name: "more than one UNENROLL dispatch, tamper protection feature flag disabled",
			st: func() coordinator.State {
				return coordinator.State{
					Components: []runtime.ComponentComponentState{
						makeComponentState("endpoint", []string{"UNENROLL"}),
						makeComponentState("foobar", []string{"UNENROLL", "FOOBAR"}),
						makeComponentState("osquery", nil),
					},
				}
			}(),
			wantPerformedActions: 0,
		},
		{
			name: "more than one UNENROLL dispatch, tamper protection feature flag enabled",
			st: func() coordinator.State {
				return coordinator.State{
					Components: []runtime.ComponentComponentState{
						makeComponentState("endpoint", []string{"UNENROLL"}),
						makeComponentState("foobar", []string{"UNENROLL", "FOOBAR"}),
						makeComponentState("osquery", nil),
					},
				}
			}(),
			tamperProtectionFn:   getTamperProtectionFunc(true),
			wantPerformedActions: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer acker.Clear()
			defer coord.Clear()

			coord.st = tc.st

			if tc.tamperProtectionFn == nil {
				handler.tamperProtectionFn = getTamperProtectionFunc(false)
			} else {
				handler.tamperProtectionFn = tc.tamperProtectionFn
			}

			err := handler.Handle(ctx, action, acker)

			require.ErrorIs(t, err, tc.wantErr)
			if tc.wantErr == nil {
				require.Len(t, acker.Acked, 1)
			}
			require.Equal(t, tc.wantPerformedActions, coord.performedActions)
		})
	}
}
