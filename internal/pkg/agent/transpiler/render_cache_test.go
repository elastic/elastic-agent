// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/mapstr"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
)

// fakeFetchProvider is a fetch context provider whose values can change between renders.
type fakeFetchProvider struct {
	values map[string]string
}

func (f *fakeFetchProvider) Run(context.Context, corecomp.ContextProviderComm) error { return nil }

func (f *fakeFetchProvider) Fetch(name string) (string, bool) {
	v, ok := f.values[name]
	return v, ok
}

func renderTestInputs(t *testing.T) Node {
	t.Helper()
	ast, err := NewAST(map[string]interface{}{
		"inputs": []interface{}{
			map[string]interface{}{"id": "static", "type": "log", "paths": []interface{}{"/var/log/static.log"}},
			map[string]interface{}{"id": "dynamic", "type": "log", "paths": []interface{}{"${dyn.path}"}},
			map[string]interface{}{"id": "fetched", "type": "log", "password": "${secrets.password}"},
		},
	})
	require.NoError(t, err)
	inputs, ok := Lookup(ast, "inputs")
	require.True(t, ok)
	return inputs
}

func renderTestContextVars(t *testing.T, fetch mapstr.M, key string) *Vars {
	t.Helper()
	v, err := NewVars("", map[string]interface{}{"env": map[string]interface{}{"HOME": "/root"}}, fetch, "env")
	require.NoError(t, err)
	v.SetCacheKey(key)
	return v
}

func renderTestDynamicVars(t *testing.T, fetch mapstr.M, id, path, key string) *Vars {
	t.Helper()
	v, err := NewVarsWithProcessors(id, map[string]interface{}{
		"env": map[string]interface{}{"HOME": "/root"},
		"dyn": map[string]interface{}{"path": path},
	}, "dyn", Processors{{"add_fields": map[string]interface{}{"target": "dyn", "fields": map[string]interface{}{"id": id}}}}, fetch, "env", "dyn")
	require.NoError(t, err)
	v.SetCacheKey(key)
	return v
}

func mapPointer(v interface{}) uintptr {
	return reflect.ValueOf(v).Pointer()
}

// byID indexes the rendered inputs by their id; inputs are rendered vars set by vars set so
// their order is not the order of the policy.
func byID(t *testing.T, maps []interface{}) map[string]map[string]interface{} {
	t.Helper()
	result := make(map[string]map[string]interface{}, len(maps))
	for _, m := range maps {
		input := m.(map[string]interface{})
		result[input["id"].(string)] = input
	}
	return result
}

func TestRenderInputsCached(t *testing.T) {
	secrets := &fakeFetchProvider{values: map[string]string{"secrets.password": "hunter2"}}
	fetch := mapstr.M{"secrets": secrets}
	inputs := renderTestInputs(t)
	original := toInterface(inputs)

	cache := NewRenderCache()
	vars := []*Vars{
		renderTestContextVars(t, fetch, "ctx"),
		renderTestDynamicVars(t, fetch, "dyn-1", "/p1", "ctx;dyn-1"),
	}
	first, err := RenderInputsCached(inputs, vars, cache)
	require.NoError(t, err)
	firstMaps := byID(t, first.Maps())
	require.Len(t, firstMaps, 3)
	assert.Equal(t, []interface{}{"/p1"}, firstMaps["dynamic-dyn-1"]["paths"])
	assert.Equal(t, "hunter2", firstMaps["fetched"]["password"])
	assert.Equal(t, map[string]RenderedInputInfo{
		"dynamic-dyn-1": {DynamicProvider: "dyn", ProviderVars: []string{"dyn.path"}},
	}, first.Info)
	// static and dynamic inputs against the context vars, dynamic input against the dynamic
	// vars; the input using the fetch provider is never cached and the static input isn't
	// rendered against the dynamic vars at all
	assert.Equal(t, 3, cache.Len())

	t.Run("unchanged vars reuse the rendered inputs", func(t *testing.T) {
		secrets.values["secrets.password"] = "changed"
		second, err := RenderInputsCached(inputs, vars, cache)
		require.NoError(t, err)
		secondMaps := byID(t, second.Maps())
		require.Len(t, secondMaps, 3)
		assert.Equal(t, mapPointer(firstMaps["static"]), mapPointer(secondMaps["static"]))
		assert.Equal(t, mapPointer(firstMaps["dynamic-dyn-1"]), mapPointer(secondMaps["dynamic-dyn-1"]))
		// the fetched value is resolved every time
		assert.NotEqual(t, mapPointer(firstMaps["fetched"]), mapPointer(secondMaps["fetched"]))
		assert.Equal(t, "changed", secondMaps["fetched"]["password"])
		assert.Equal(t, first.Info, second.Info)
		assert.Equal(t, 3, cache.Len())
	})

	t.Run("changed dynamic vars re-render only their inputs", func(t *testing.T) {
		vars := []*Vars{
			vars[0],
			renderTestDynamicVars(t, fetch, "dyn-2", "/p2", "ctx;dyn-2"),
		}
		third, err := RenderInputsCached(inputs, vars, cache)
		require.NoError(t, err)
		thirdMaps := byID(t, third.Maps())
		require.Len(t, thirdMaps, 3)
		assert.Equal(t, mapPointer(firstMaps["static"]), mapPointer(thirdMaps["static"]))
		assert.Equal(t, []interface{}{"/p2"}, thirdMaps["dynamic-dyn-2"]["paths"])
		assert.Equal(t, map[string]RenderedInputInfo{
			"dynamic-dyn-2": {DynamicProvider: "dyn", ProviderVars: []string{"dyn.path"}},
		}, third.Info)
		// the entries of dyn-1 were swept
		assert.Equal(t, 3, cache.Len())
	})

	t.Run("a fetch provider appearing invalidates the entries", func(t *testing.T) {
		// an input referencing a provider that isn't running is cached as removed
		noFetch := []*Vars{renderTestContextVars(t, mapstr.M{}, "ctx")}
		rendered, err := RenderInputsCached(inputs, noFetch, cache)
		require.NoError(t, err)
		require.Len(t, rendered.Maps(), 1)
		// once the fetch provider runs the vars key changes (the controller includes the fetch
		// providers in it) and the input is rendered again
		withFetch := []*Vars{renderTestContextVars(t, fetch, "ctx;fetch=secrets")}
		rendered, err = RenderInputsCached(inputs, withFetch, cache)
		require.NoError(t, err)
		require.Len(t, rendered.Maps(), 2)
	})

	t.Run("reset drops the entries", func(t *testing.T) {
		cache.Reset()
		assert.Equal(t, 0, cache.Len())
		rendered, err := RenderInputsCached(inputs, vars, cache)
		require.NoError(t, err)
		assert.NotEqual(t, mapPointer(firstMaps["static"]), mapPointer(byID(t, rendered.Maps())["static"]))
		assert.Equal(t, 3, cache.Len())
	})

	t.Run("vars without a cache key are not cached", func(t *testing.T) {
		cache := NewRenderCache()
		vars := []*Vars{
			renderTestContextVars(t, fetch, ""),
			renderTestDynamicVars(t, fetch, "dyn-1", "/p1", ""),
		}
		rendered, err := RenderInputsCached(inputs, vars, cache)
		require.NoError(t, err)
		require.Len(t, rendered.Maps(), 3)
		assert.Equal(t, 0, cache.Len())
	})

	t.Run("a nil cache renders every time", func(t *testing.T) {
		rendered, err := RenderInputsCached(inputs, vars, nil)
		require.NoError(t, err)
		require.Len(t, rendered.Maps(), 3)
		assert.Equal(t, toInterface(rendered.Node()), rendered.Maps())
	})

	// the inputs being rendered are never modified
	assert.Equal(t, original, toInterface(inputs))
}

func TestApplySharesUnchangedNodes(t *testing.T) {
	ast, err := NewAST(map[string]interface{}{
		"static": map[string]interface{}{"b": "value", "list": []interface{}{"x", 1}},
		"dynamic": map[string]interface{}{
			"home":   "${env.HOME}",
			"static": "unchanged",
			"list":   []interface{}{"x", "${env.HOME}"},
		},
	})
	require.NoError(t, err)
	vars, err := NewVars("", map[string]interface{}{"env": map[string]interface{}{"HOME": "/root"}}, nil, "env")
	require.NoError(t, err)

	root := ast.root.(*Dict)
	applied, err := root.Apply(vars)
	require.NoError(t, err)
	appliedDict := applied.(*Dict)
	require.NotSame(t, root, appliedDict)
	assert.Equal(t, map[string]interface{}{
		"static": map[string]interface{}{"b": "value", "list": []interface{}{"x", 1}},
		"dynamic": map[string]interface{}{
			"home":   "/root",
			"static": "unchanged",
			"list":   []interface{}{"x", "/root"},
		},
	}, toInterface(appliedDict))

	// the subtree without variables is the original node
	staticOrig, _ := root.Find("static")
	staticNew, _ := appliedDict.Find("static")
	assert.Same(t, staticOrig, staticNew)
	// the subtree with variables is new, but its unchanged children are the originals
	dynOrig, _ := root.Find("dynamic")
	dynNew, _ := appliedDict.Find("dynamic")
	require.NotSame(t, dynOrig, dynNew)
	unchangedOrig, _ := dynOrig.Find("static")
	unchangedNew, _ := dynNew.Find("static")
	assert.Same(t, unchangedOrig, unchangedNew)
	homeOrig, _ := dynOrig.Find("home")
	homeNew, _ := dynNew.Find("home")
	assert.NotSame(t, homeOrig, homeNew)

	// a tree without variables is returned as is
	staticOnly, err := NewAST(map[string]interface{}{"a": map[string]interface{}{"b": []interface{}{"c"}}})
	require.NoError(t, err)
	same, err := staticOnly.root.Apply(vars)
	require.NoError(t, err)
	assert.Same(t, staticOnly.root, same)
}

func TestApplyDoesNotModifyVarsTree(t *testing.T) {
	// a variable replaced by a whole object gets the processors attached to the object; the
	// object comes from the vars tree that is shared by every render, so it must be a copy
	ast, err := NewAST(map[string]interface{}{"config": "${dyn.obj}"})
	require.NoError(t, err)
	processors := Processors{{"add_fields": map[string]interface{}{"fields": map[string]interface{}{"a": "b"}}}}
	vars, err := NewVarsWithProcessors("id", map[string]interface{}{
		"dyn": map[string]interface{}{"obj": map[string]interface{}{"k": "v"}},
	}, "dyn", processors, nil, "", "dyn")
	require.NoError(t, err)

	applied, err := ast.root.Apply(vars)
	require.NoError(t, err)
	assert.Equal(t, processors, applied.Processors())

	obj, ok := Lookup(vars.tree, "dyn.obj")
	require.True(t, ok)
	assert.Nil(t, obj.(*Key).value.(*Dict).processors)
}
