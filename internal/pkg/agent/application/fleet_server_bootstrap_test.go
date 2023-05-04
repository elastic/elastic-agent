// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/component"
)

func TestFleetServerComponentModifier_NoServerConfig(t *testing.T) {
	cfg := map[string]interface{}{}
	modifier := FleetServerComponentModifier(nil)
	fleetServerInputSource, err := structpb.NewStruct(map[string]interface{}{
		"id":   "fleet-server",
		"type": "fleet-server",
	})
	require.NoError(t, err)
	fleetServerOutputSource, err := structpb.NewStruct(map[string]interface{}{
		"type":  "elasticsearch",
		"hosts": []interface{}{"localhost:9200"},
	})
	require.NoError(t, err)

	fleetServerComponent := component.Component{
		InputSpec: &component.InputRuntimeSpec{
			InputType: "fleet-server",
		},
		Units: []component.Unit{
			{
				Type: client.UnitTypeInput,
				Config: &proto.UnitExpectedConfig{
					Type:   "fleet-server",
					Source: fleetServerInputSource,
				},
			},
			{
				Type: client.UnitTypeOutput,
				Config: &proto.UnitExpectedConfig{
					Type:   "elasticsearch",
					Source: fleetServerOutputSource,
				},
			},
		},
	}
	comps := []component.Component{fleetServerComponent}
	resComps, err := modifier(comps, cfg)
	require.NoError(t, err)

	if assert.Len(t, resComps, 1) {
		assert.ErrorIs(t, resComps[0].Err, ErrFleetServerNotBootstrapped)
		if assert.Len(t, resComps[0].Units, 2) {
			assert.ErrorIs(t, resComps[0].Units[0].Err, ErrFleetServerNotBootstrapped)
			assert.ErrorIs(t, resComps[0].Units[1].Err, ErrFleetServerNotBootstrapped)
		}

	}
}

func TestInjectFleetConfigComponentModifier(t *testing.T) {
	fleetConfig := &configuration.FleetAgentConfig{
		Enabled: true,
		Client: remote.Config{
			Host: "sample.host",
		},
	}

	cfg := map[string]interface{}{
		"host": map[string]interface{}{
			"id": "agent-id",
		},
	}

	modifier := InjectFleetConfigComponentModifier(fleetConfig, nil)
	apmSource, err := structpb.NewStruct(map[string]interface{}{
		"sample": "config",
	})
	require.NoError(t, err)

	apmComponent := component.Component{
		InputSpec: &component.InputRuntimeSpec{
			InputType: "apm",
		},
		Units: []component.Unit{
			{
				Type: client.UnitTypeInput,
				Config: &proto.UnitExpectedConfig{
					Type:   "apm",
					Source: apmSource,
				},
			},
		},
	}
	comps := []component.Component{apmComponent}
	resComps, err := modifier(comps, cfg)
	require.NoError(t, err)

	require.Equal(t, 1, len(resComps))
	require.Equal(t, 1, len(resComps[0].Units))
	resConfig := resComps[0].Units[0].Config.Source.AsMap()
	fleet, ok := resConfig["fleet"]
	require.True(t, ok)

	fleetMap, ok := fleet.(map[string]interface{})
	require.True(t, ok)

	hostRaw, found := fleetMap["host"]
	require.True(t, found)

	hostsRaw, found := fleetMap["hosts"]
	require.True(t, found)

	hostMap, ok := hostRaw.(map[string]interface{})
	require.True(t, ok)

	idRaw, found := hostMap["id"]
	require.True(t, found)
	require.Equal(t, "agent-id", idRaw.(string))

	hostsSlice, ok := hostsRaw.([]interface{})
	require.True(t, ok)
	require.Equal(t, 1, len(hostsSlice))
	require.Equal(t, "sample.host", hostsSlice[0].(string))

}

func TestFleetServerBootstrapManager(t *testing.T) {
	l := testutils.NewErrorLogger(t)
	mgr := newFleetServerBootstrapManager(l)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	g, _ := errgroup.WithContext(ctx)

	var change coordinator.ConfigChange
	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case err := <-mgr.Errors():
				cancel()
				return err
			case change = <-mgr.Watch():
				cancel()
			}
		}
	})

	g.Go(func() error {
		return mgr.Run(ctx)
	})

	err := g.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		require.NoError(t, err)
	}

	require.NotNil(t, change)
	assert.NotNil(t, change.Config())
}

type testLogLevelProvider struct {
	logLevel string
}

func (l *testLogLevelProvider) LogLevel() string {
	return l.logLevel
}

func TestInjectAgentLoggingLevel(t *testing.T) {
	tests := []struct {
		name string
		cfg  map[string]interface{}
		llp  logLevelProvider
		res  map[string]interface{}
	}{
		{
			name: "nil",
		},
		{
			name: "empty",
			cfg:  map[string]interface{}{},
			llp:  &testLogLevelProvider{"debug"},
			res:  map[string]interface{}{"agent": map[string]interface{}{"logging": map[string]interface{}{"level": string("debug")}}},
		},
		{
			name: "existing agent",
			cfg:  map[string]interface{}{"agent": map[string]interface{}{"id": "123456"}},
			llp:  &testLogLevelProvider{"info"},
			res:  map[string]interface{}{"agent": map[string]interface{}{"id": "123456", "logging": map[string]interface{}{"level": string("info")}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			injectAgentLoggingLevel(tc.cfg, tc.llp)
			diff := cmp.Diff(tc.res, tc.cfg)
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
