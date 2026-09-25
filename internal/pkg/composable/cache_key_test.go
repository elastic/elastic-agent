// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package composable

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
)

type cacheKeyFetchProvider struct{}

func (cacheKeyFetchProvider) Run(context.Context, corecomp.ContextProviderComm) error { return nil }
func (cacheKeyFetchProvider) Fetch(string) (string, bool)                             { return "", false }

func varsCacheKeys(vars []*transpiler.Vars) []string {
	keys := make([]string, 0, len(vars))
	for _, v := range vars {
		keys = append(keys, v.CacheKey())
	}
	return keys
}

func TestGenerateVarsCacheKeys(t *testing.T) {
	ctxState := &contextProviderState{}
	require.NoError(t, ctxState.Set(map[string]interface{}{"a": "1"}))
	dynState := &dynamicProviderState{mappings: map[string]dynamicProviderMapping{}}
	require.NoError(t, dynState.AddOrUpdate("p1", 0, map[string]interface{}{"x": "1"}, nil))
	require.NoError(t, dynState.AddOrUpdate("p2", 0, map[string]interface{}{"x": "1"}, nil))
	c := &controller{
		contextProviderStates: map[string]*contextProviderState{"ctx": ctxState},
		dynamicProviderStates: map[string]*dynamicProviderState{"dyn": dynState},
	}

	keys := varsCacheKeys(c.generateVars(mapstr.M{}, "env"))
	require.Len(t, keys, 3)
	assert.NotEmpty(t, keys[0])
	assert.NotEqual(t, keys[0], keys[1])
	assert.NotEqual(t, keys[1], keys[2])

	t.Run("same content keeps the keys", func(t *testing.T) {
		require.NoError(t, ctxState.Set(map[string]interface{}{"a": "1"}))
		require.NoError(t, dynState.AddOrUpdate("p1", 0, map[string]interface{}{"x": "1"}, nil))
		assert.Equal(t, keys, varsCacheKeys(c.generateVars(mapstr.M{}, "env")))
	})

	t.Run("changed dynamic mapping changes its key only", func(t *testing.T) {
		require.NoError(t, dynState.AddOrUpdate("p1", 0, map[string]interface{}{"x": "2"}, nil))
		changed := varsCacheKeys(c.generateVars(mapstr.M{}, "env"))
		assert.Equal(t, keys[0], changed[0])
		assert.NotEqual(t, keys[1], changed[1])
		assert.Equal(t, keys[2], changed[2])

		// changed processors as well
		require.NoError(t, dynState.AddOrUpdate("p1", 0, map[string]interface{}{"x": "2"},
			[]map[string]interface{}{{"add_fields": map[string]interface{}{"fields": map[string]interface{}{"a": 1}}}}))
		withProcessors := varsCacheKeys(c.generateVars(mapstr.M{}, "env"))
		assert.NotEqual(t, changed[1], withProcessors[1])
		assert.Equal(t, changed[2], withProcessors[2])
		keys = withProcessors
	})

	t.Run("changed context mapping changes every key", func(t *testing.T) {
		require.NoError(t, ctxState.Set(map[string]interface{}{"a": "2"}))
		changed := varsCacheKeys(c.generateVars(mapstr.M{}, "env"))
		for i := range keys {
			assert.NotEqual(t, keys[i], changed[i])
		}
		keys = changed
	})

	t.Run("fetch providers and default provider are part of the keys", func(t *testing.T) {
		withFetch := varsCacheKeys(c.generateVars(mapstr.M{"secrets": cacheKeyFetchProvider{}}, "env"))
		otherDefault := varsCacheKeys(c.generateVars(mapstr.M{}, "host"))
		for i := range keys {
			assert.NotEqual(t, keys[i], withFetch[i])
			assert.NotEqual(t, keys[i], otherDefault[i])
		}
	})

	t.Run("removed mapping is gone", func(t *testing.T) {
		dynState.Remove("p1")
		assert.Len(t, c.generateVars(mapstr.M{}, "env"), 2)
	})
}
