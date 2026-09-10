// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/elastic/elastic-agent/pkg/component"
)

// TestCoordinator_generateComponentModel_reusesUnchangedWork checks that a refresh with unchanged
// vars reuses the unit configurations of the previous refresh and that the result is the same
// as a refresh with cold caches.
func TestCoordinator_generateComponentModel_reusesUnchangedWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord := k8sBenchCoordinator(t, ctx, k8sBenchVars(t, true))

	require.NoError(t, coord.generateComponentModel())
	first := coord.componentModel
	require.NotEmpty(t, first)
	require.NotZero(t, coord.renderCache.Len())
	require.NotZero(t, coord.expectedConfigCache.Len())

	require.NoError(t, coord.generateComponentModel())
	second := coord.componentModel
	require.Len(t, second, len(first))
	// components are generated in no particular order, match them by id
	for _, comp := range first {
		other := componentByID(t, second, comp.ID)
		require.Len(t, other.Units, len(comp.Units))
		for j := range comp.Units {
			assert.Equal(t, comp.Units[j].ID, other.Units[j].ID)
			assert.Same(t, comp.Units[j].Config, other.Units[j].Config)
		}
	}

	// the keys consumed while generating the components are still in the rendered policy
	inputs, ok := coord.derivedConfig["inputs"].([]interface{})
	require.True(t, ok)
	require.NotEmpty(t, inputs)
	for _, input := range inputs {
		assert.Contains(t, input.(map[string]interface{}), "use_output")
	}

	// cold caches produce the same model
	coord.renderCache.Reset()
	coord.expectedConfigCache = component.NewExpectedConfigCache()
	require.NoError(t, coord.generateComponentModel())
	cold := coord.componentModel
	require.Len(t, cold, len(first))
	for _, comp := range first {
		other := componentByID(t, cold, comp.ID)
		require.Len(t, other.Units, len(comp.Units))
		for j := range comp.Units {
			assert.Equal(t, comp.Units[j].ID, other.Units[j].ID)
			assert.NotSame(t, comp.Units[j].Config, other.Units[j].Config)
			assert.True(t, proto.Equal(comp.Units[j].Config, other.Units[j].Config))
		}
	}
}

func componentByID(t *testing.T, comps []component.Component, id string) component.Component {
	t.Helper()
	for _, comp := range comps {
		if comp.ID == id {
			return comp
		}
	}
	require.Failf(t, "component not found", "no component with id %q", id)
	return component.Component{}
}
