// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

// TestStateWatch_BufferSize verifies that StateWatch passes the requested
// buffer_size to StateSubscribe, and falls back to AllAvailable (32) when
// buffer_size is unset.
func TestStateWatch_BufferSize(t *testing.T) {
	allAvail := cproto.StateWatchBufferSizeAllAvailable
	latestOnly := cproto.StateWatchBufferSizeLatestOnly
	custom := int32(8)
	tests := []struct {
		name       string
		bufferSize *int32
		wantBufLen int
	}{
		{"unset uses AllAvailable (32)", nil, 32},
		{"LatestOnly (0) passes 0", &latestOnly, 0},
		{"AllAvailable (32) passes 32", &allAvail, 32},
		{"custom value (8) passes 8", &custom, 8},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotBufLen := make(chan int, 1)
			sub := &fakeStateSubscriber{
				subscribeFunc: func(ctx context.Context, bufferLen int) chan coordinator.State {
					gotBufLen <- bufferLen
					ch := make(chan coordinator.State)
					go func() { <-ctx.Done(); close(ch) }()
					return ch
				},
			}

			s := &Server{
				stateSub:  sub,
				agentInfo: new(info.AgentInfo),
			}

			lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "localhost:0")
			require.NoError(t, err)
			grpcSrv := grpc.NewServer()
			cproto.RegisterElasticAgentControlServer(grpcSrv, s)
			go grpcSrv.Serve(lis) //nolint:errcheck // server stops via grpcSrv.Stop() in defer
			defer grpcSrv.Stop()

			conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()

			stream, err := cproto.NewElasticAgentControlClient(conn).StateWatch(ctx, &cproto.StateWatchRequest{BufferSize: tc.bufferSize})
			require.NoError(t, err)
			_ = stream

			select {
			case buf := <-gotBufLen:
				assert.Equal(t, tc.wantBufLen, buf)
			case <-ctx.Done():
				t.Fatal("timed out waiting for StateSubscribe to be called")
			}
		})
	}
}

type fakeStateSubscriber struct {
	subscribeFunc func(ctx context.Context, bufferLen int) chan coordinator.State
}

func (f *fakeStateSubscriber) StateSubscribe(ctx context.Context, bufferLen int) chan coordinator.State {
	return f.subscribeFunc(ctx, bufferLen)
}

func TestStateMapping(t *testing.T) {
	now := time.Now()
	testcases := []struct {
		name           string
		agentState     cproto.State
		agentMessage   string
		fleetState     cproto.State
		fleetMessage   string
		upgradeDetails *details.Details
	}{
		{
			name:         "waiting first checkin response",
			agentState:   cproto.State_HEALTHY,
			agentMessage: "Healthy",
			fleetState:   cproto.State_STARTING,
			fleetMessage: "",
		},
		{
			name:         "last checkin successful",
			agentState:   cproto.State_HEALTHY,
			agentMessage: "Healthy",
			fleetState:   cproto.State_HEALTHY,
			fleetMessage: "Connected",
		},
		{
			name:         "last checkin failed",
			agentState:   cproto.State_HEALTHY,
			agentMessage: "Healthy",
			fleetState:   cproto.State_FAILED,
			fleetMessage: "<error value coming from fleet gateway>",
		},
		{
			name:         "with upgrade details",
			agentState:   cproto.State_UPGRADING,
			agentMessage: "Upgrading to version 8.13.0",
			fleetState:   cproto.State_STOPPED,
			fleetMessage: "Not enrolled into Fleet",
			upgradeDetails: &details.Details{
				TargetVersion: "8.13.0",
				State:         details.StateDownloading,
				ActionID:      "some-action-id",
				Metadata: details.Metadata{
					ScheduledAt:     &now,
					DownloadPercent: 1.7,
					ErrorMsg:        "some error",
					RetryUntil:      &now,
					RetryErrorMsg:   "some retryable error",
					FailedState:     details.StateWatching,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			inputState := &coordinator.State{
				State:        tc.agentState,
				Message:      tc.agentMessage,
				FleetState:   tc.fleetState,
				FleetMessage: tc.fleetMessage,
				LogLevel:     logp.ErrorLevel,
				Components: []runtime.ComponentComponentState{
					{
						Component: component.Component{
							ID: "some-component",
							InputSpec: &component.InputRuntimeSpec{
								InputType: "some-component-input-type",
							},
							Units: []component.Unit{
								{
									ID:   "some-input-unit",
									Type: client.UnitTypeInput,
								},
							},
						},
						State: runtime.ComponentState{
							State:   client.UnitStateHealthy,
							Message: "component healthy",
							VersionInfo: runtime.ComponentVersionInfo{
								Name: "awesome-comp",
								Meta: map[string]string{
									"foo": "bar",
								},
							},
							Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
								{
									UnitType: client.UnitTypeInput,
									UnitID:   "some-input-unit",
								}: {
									State:   client.UnitStateHealthy,
									Message: "unit healthy",
									Payload: map[string]any{
										"foo": map[string]any{
											"bar": "baz"},
									},
								},
							},
						},
					},
				},
				Collector: &status.AggregateStatus{
					Event: componentstatus.NewEvent(componentstatus.StatusOK),
					ComponentStatusMap: map[string]*status.AggregateStatus{
						"some-pipeline": &status.AggregateStatus{
							Event: componentstatus.NewEvent(componentstatus.StatusOK),
							ComponentStatusMap: map[string]*status.AggregateStatus{
								"receiver": &status.AggregateStatus{
									Event: componentstatus.NewEvent(componentstatus.StatusOK),
								},
							},
						},
					},
				},
			}

			if tc.upgradeDetails != nil {
				inputState.UpgradeDetails = &details.Details{
					TargetVersion: tc.upgradeDetails.TargetVersion,
					State:         tc.upgradeDetails.State,
					ActionID:      tc.upgradeDetails.ActionID,
					Metadata:      tc.upgradeDetails.Metadata,
				}
			}

			agentInfo := new(info.AgentInfo)

			stateResponse, err := stateToProto(inputState, agentInfo)
			require.NoError(t, err)

			assert.Equal(t, stateResponse.State, tc.agentState)
			assert.Equal(t, stateResponse.Message, tc.agentMessage)
			assert.Equal(t, stateResponse.FleetState, tc.fleetState)
			assert.Equal(t, stateResponse.FleetMessage, tc.fleetMessage)
			if assert.Len(t, stateResponse.Components, 1) {
				expectedCompState := &cproto.ComponentState{
					Id:      "some-component",
					State:   cproto.State_HEALTHY,
					Name:    "some-component-input-type",
					Message: "component healthy",
					Units: []*cproto.ComponentUnitState{
						{
							UnitId:   "some-input-unit",
							UnitType: cproto.UnitType_INPUT,
							State:    cproto.State_HEALTHY,
							Message:  "unit healthy",
							Payload:  "{\"foo\":{\"bar\":\"baz\"}}",
						},
					},
					VersionInfo: &cproto.ComponentVersionInfo{
						Name: "awesome-comp",
						Meta: map[string]string{"foo": "bar"},
					},
				}
				assert.Equal(t, expectedCompState, stateResponse.Components[0])
			}
			if assert.NotNil(t, stateResponse.Collector) {
				assert.Equal(t, cproto.CollectorComponentStatus_StatusOK, stateResponse.Collector.Status)
				if assert.Contains(t, stateResponse.Collector.ComponentStatusMap, "some-pipeline") {
					observed := stateResponse.Collector.ComponentStatusMap["some-pipeline"]
					assert.Equal(t, cproto.CollectorComponentStatus_StatusOK, observed.Status)
					assert.NotEmpty(t, observed.Timestamp)
					if assert.Contains(t, observed.ComponentStatusMap, "receiver") {
						observedReceiver := observed.ComponentStatusMap["receiver"]
						assert.Equal(t, cproto.CollectorComponentStatus_StatusOK, observedReceiver.Status)
						assert.NotEmpty(t, observedReceiver.Timestamp)
					}
				}
			}

			if tc.upgradeDetails != nil {
				expectedMetadata := &cproto.UpgradeDetailsMetadata{
					DownloadPercent: float32(tc.upgradeDetails.Metadata.DownloadPercent),
					FailedState:     string(tc.upgradeDetails.Metadata.FailedState),
					ErrorMsg:        tc.upgradeDetails.Metadata.ErrorMsg,
					RetryErrorMsg:   tc.upgradeDetails.Metadata.RetryErrorMsg,
				}

				if tc.upgradeDetails.Metadata.ScheduledAt != nil &&
					!tc.upgradeDetails.Metadata.ScheduledAt.IsZero() {
					expectedMetadata.ScheduledAt = tc.upgradeDetails.Metadata.ScheduledAt.Format(control.TimeFormat())
				}

				if tc.upgradeDetails.Metadata.RetryUntil != nil &&
					!tc.upgradeDetails.Metadata.RetryUntil.IsZero() {
					expectedMetadata.RetryUntil = tc.upgradeDetails.Metadata.RetryUntil.Format(control.TimeFormat())
				}

				assert.Equal(t, string(tc.upgradeDetails.State), stateResponse.UpgradeDetails.State)
				assert.Equal(t, tc.upgradeDetails.TargetVersion, stateResponse.UpgradeDetails.TargetVersion)
				assert.Equal(t, tc.upgradeDetails.ActionID, stateResponse.UpgradeDetails.ActionId)
				assert.Equal(t, expectedMetadata, stateResponse.UpgradeDetails.Metadata)
			}
		})
	}
}
