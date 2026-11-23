// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

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
