// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	gproto "google.golang.org/protobuf/proto"

	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths/pathstest"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/internal/pkg/otel/unitserver"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestInjectControlProtocolConnections(t *testing.T) {
	log, _ := loggertest.New("test")
	unitServer, err := unitserver.New(log, "unix://"+filepath.Join(t.TempDir(), "units.sock"), &info.AgentInfo{}, 1024)
	require.NoError(t, err)
	m := &OTelManager{unitServer: unitServer}

	comp := func(schedule string) component.Component {
		return component.Component{
			ID:             "synthetics/tcp-default",
			RuntimeManager: component.OtelRuntimeManager,
			InputSpec: &component.InputRuntimeSpec{
				BinaryName: "elastic-otel-collector",
				Spec: component.InputSpec{
					Name:                 "synthetics/tcp",
					Command:              &component.CommandSpec{Args: []string{"heartbeat"}},
					SingleReceiver:       true,
					ControlProtocolUnits: true,
				},
			},
			Units: []component.Unit{{
				ID:     "monitor-a",
				Type:   client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{"type": "synthetics/tcp", "schedule": schedule}),
			}},
		}
	}
	otherComp := component.Component{ID: "filestream-default", RuntimeManager: component.OtelRuntimeManager}

	secret := func(components []component.Component) string {
		unitServer.Update(components)
		conf := confmap.New()
		require.NoError(t, m.injectControlProtocolConnections(conf, components))
		receiverID, err := translate.GetControlProtocolReceiverID(&components[0])
		require.NoError(t, err)
		// only the receiver of the component with control protocol units gets connection info
		receivers, err := conf.Sub("receivers")
		require.NoError(t, err)
		assert.Len(t, receivers.ToStringMap(), 1)
		value, ok := conf.Get("receivers::" + receiverID.String() + "::management::agent::connection_secret").(string)
		require.True(t, ok, "no connection secret in %v", conf.ToStringMap())
		return value
	}

	first := secret([]component.Component{comp("@every 1m"), otherComp})
	decoded, err := base64.StdEncoding.DecodeString(first)
	require.NoError(t, err)
	var startUpInfo proto.StartUpInfo
	require.NoError(t, gproto.Unmarshal(decoded, &startUpInfo))
	assert.NotEmpty(t, startUpInfo.Token)
	assert.NotEmpty(t, startUpInfo.PeerKey)

	// Changing the units keeps the connection info, so the receiver config stays the same.
	assert.Equal(t, first, secret([]component.Component{comp("@every 5m"), otherComp}))
}

// The connection info must reach the receiver in the config the manager sends to
// the collector, alongside the receiver's own config.
func TestBuildMergedConfigInjectsControlProtocolConnections(t *testing.T) {
	pathstest.SetTop(t, t.TempDir())

	log, _ := loggertest.New("test")
	unitServer, err := unitserver.New(log, "unix://"+filepath.Join(t.TempDir(), "units.sock"), &info.AgentInfo{}, 1024)
	require.NoError(t, err)
	m := &OTelManager{healthCheckExtComponentID: "healthcheckv2/test", unitServer: unitServer}

	comp := component.Component{
		ID:             "synthetics/tcp-default",
		InputType:      "synthetics/tcp",
		OutputType:     "elasticsearch",
		OutputName:     "default",
		RuntimeManager: component.OtelRuntimeManager,
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name:                 "synthetics/tcp",
				Command:              &component.CommandSpec{Args: []string{"heartbeat"}},
				SingleReceiver:       true,
				ControlProtocolUnits: true,
			},
		},
		Units: []component.Unit{
			{
				ID:     "synthetics/tcp-default-monitor-a",
				Type:   client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{"id": "monitor-a", "type": "synthetics/tcp"}),
			},
			{
				ID:   "synthetics/tcp-default",
				Type: client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{
					"type":  "elasticsearch",
					"hosts": []any{"localhost:9200"},
				}),
			},
		},
	}
	components := []component.Component{comp}
	unitServer.Update(components)

	result, err := m.buildMergedConfig(t.Context(), configUpdate{components: components}, &info.AgentInfo{}, logp.NewNopLogger())
	require.NoError(t, err)
	require.NotNil(t, result)

	receiverID, err := translate.GetControlProtocolReceiverID(&comp)
	require.NoError(t, err)
	receiverKey := "receivers::" + receiverID.String()
	secret, ok := result.Get(receiverKey + "::management::agent::connection_secret").(string)
	require.True(t, ok, "no connection secret for %s in %v", receiverID, result.ToStringMap()["receivers"])
	assert.NotEmpty(t, secret)
	assert.True(t, result.IsSet(receiverKey+"::heartbeat"), "the receiver should keep its own config")
}

// If the unit server can't start, the next update must try again, and the
// receiver config must still get its connection info.
func TestUpdateUnitServerRetriesStart(t *testing.T) {
	log, _ := loggertest.New("test")
	// A socket under a regular file can't be created.
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	unitServer, err := unitserver.New(log, "unix://"+filepath.Join(file, "units.sock"), &info.AgentInfo{}, 1024)
	require.NoError(t, err)
	m := &OTelManager{unitServer: unitServer, managerLogger: log}

	comp := component.Component{
		ID:             "synthetics/tcp-default",
		RuntimeManager: component.OtelRuntimeManager,
		InputSpec: &component.InputRuntimeSpec{
			Spec: component.InputSpec{SingleReceiver: true, ControlProtocolUnits: true},
		},
	}
	m.updateUnitServer(t.Context(), []component.Component{comp})
	assert.False(t, m.unitServerStarted, "a server that failed to start should be started again on the next update")
	_, err = unitServer.ConnectionInfo(comp.ID)
	assert.NoError(t, err, "the units should be kept even if the server isn't running")
}

// A component whose receiver doesn't check in is degraded, and fails with all
// its units once the receiver missed maxReceiverCheckinMisses check-ins, as a
// beat process would.
func TestReportMissedCheckins(t *testing.T) {
	log, _ := loggertest.New("test")
	// A socket under a regular file can't be created, so the receiver can't
	// check in.
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	unitServer, err := unitserver.New(log, "unix://"+filepath.Join(file, "units.sock"), &info.AgentInfo{}, 1024)
	require.NoError(t, err)
	const period = 50 * time.Millisecond
	m := &OTelManager{
		unitServer:               unitServer,
		managerLogger:            log,
		checkinPeriod:            period,
		componentStateCh:         make(chan []runtime.ComponentComponentState, 100),
		currentComponentStates:   make(map[string]runtime.ComponentComponentState),
		collectorComponentStates: make(map[string]runtime.ComponentComponentState),
	}

	inputKey := runtime.ComponentUnitKey{UnitID: "monitor-a", UnitType: client.UnitTypeInput}
	outputKey := runtime.ComponentUnitKey{UnitID: "output", UnitType: client.UnitTypeOutput}
	comp := component.Component{
		ID:             "synthetics/tcp-default",
		RuntimeManager: component.OtelRuntimeManager,
		InputSpec: &component.InputRuntimeSpec{
			Spec: component.InputSpec{SingleReceiver: true, ControlProtocolUnits: true},
		},
		Units: []component.Unit{
			{ID: inputKey.UnitID, Type: inputKey.UnitType, Config: component.MustExpectedConfig(map[string]any{"type": "synthetics/tcp"})},
			{ID: outputKey.UnitID, Type: outputKey.UnitType, Config: component.MustExpectedConfig(map[string]any{"type": "elasticsearch"})},
		},
	}
	m.components = []component.Component{comp}
	m.updateUnitServer(t.Context(), m.components)
	require.Error(t, m.unitServerErr)

	// The collector reports the component as healthy, with the input unit not
	// yet run by the receiver.
	collectorState := runtime.ComponentComponentState{
		Component: comp,
		State: runtime.ComponentState{
			State:   client.UnitStateHealthy,
			Message: "Healthy",
			Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
				inputKey:  {State: client.UnitStateStarting},
				outputKey: {State: client.UnitStateHealthy},
			},
		},
	}
	m.collectorComponentStates[comp.ID] = collectorState
	m.currentComponentStates[comp.ID] = collectorState

	// reported waits for the component to be reported in the given state.
	reported := func(state client.UnitState) runtime.ComponentState {
		var last runtime.ComponentState
		require.Eventually(t, func() bool {
			m.reportMissedCheckins(t.Context())
			for {
				select {
				case updates := <-m.componentStateCh:
					require.Len(t, updates, 1)
					last = updates[0].State
				default:
					return last.State == state
				}
			}
		}, 10*time.Second, period/5, "the component should be %s", state)
		return last
	}

	degraded := reported(client.UnitStateDegraded)
	assert.Contains(t, degraded.Message, "Degraded: the receiver missed")
	assert.Contains(t, degraded.Message, "failed to start serving its units", "the message should say why the receiver can't check in")
	assert.Equal(t, collectorState.State.Units, degraded.Units, "only the component should be degraded")

	failed := reported(client.UnitStateFailed)
	assert.Contains(t, failed.Message, "the receiver missed 3 check-ins")
	require.Len(t, failed.Units, 2)
	for key, unit := range failed.Units {
		assert.Equal(t, client.UnitStateFailed, unit.State, "unit %s should fail with the component", key.UnitID)
		assert.Equal(t, failed.Message, unit.Message)
	}
	assert.Equal(t, failed, m.currentComponentStates[comp.ID].State)
	assert.Equal(t, client.UnitStateHealthy, m.collectorComponentStates[comp.ID].State.State, "the collector's state should be kept")

	// A status update from the collector keeps the component failed.
	assert.Equal(t, client.UnitStateFailed, m.withMissedCheckins(collectorState).State.State)
}
