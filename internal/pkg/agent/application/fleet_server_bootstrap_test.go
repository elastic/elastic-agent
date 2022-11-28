// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

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

	modifier := InjectFleetConfigComponentModifier(fleetConfig)
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

	fmt.Println(hostRaw)
	fmt.Println(hostsRaw)

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
