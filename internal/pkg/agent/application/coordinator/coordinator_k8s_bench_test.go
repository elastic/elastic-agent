// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

// k8sBenchVars builds the vars the same way the composable controller does: vars[0] holds only
// context providers, every other entry is a dynamic kubernetes mapping with processors attached
// and dynamicProvider set. When keyed is true every vars set gets a cache key, as the controller
// sets, which enables the render cache.
func k8sBenchVars(b testing.TB, keyed bool) []*transpiler.Vars {
	varsMaps := []map[string]any{}
	varsMapsBytes, err := os.ReadFile("./testdata/variables.yaml")
	require.NoError(b, err)
	require.NoError(b, yaml.Unmarshal(varsMapsBytes, &varsMaps))

	vars := make([]*transpiler.Vars, 0, len(varsMaps))
	for i, vm := range varsMaps {
		k8s, hasK8s := vm["kubernetes"]
		if i == 0 || !hasK8s {
			delete(vm, "kubernetes")
			v, err := transpiler.NewVars("", vm, mapstr.M{}, "env")
			require.NoError(b, err)
			if keyed {
				v.SetCacheKey("context")
			}
			vars = append(vars, v)
			continue
		}
		processors := []map[string]any{
			{"add_fields": map[string]any{"fields": k8s, "target": "kubernetes"}},
			{"add_fields": map[string]any{"fields": map[string]any{"id": fmt.Sprintf("c-%d", i)}, "target": "container"}},
		}
		v, err := transpiler.NewVarsWithProcessors(fmt.Sprintf("kubernetes-%d", i), vm, "kubernetes", processors, mapstr.M{}, "env", "kubernetes")
		require.NoError(b, err)
		if keyed {
			v.SetCacheKey(fmt.Sprintf("context;kubernetes-%d", i))
		}
		vars = append(vars, v)
	}
	return vars
}

// BenchmarkCoordinator_generateComponentModel_k8sVars measures a full render with cold render
// cache (for example after a policy change).
func BenchmarkCoordinator_generateComponentModel_k8sVars(b *testing.B) {
	benchmarkK8sVars(b, k8sBenchVars(b, false), nil)
}

// BenchmarkCoordinator_generateComponentModel_k8sVarsUnchanged measures a render where nothing
// changed since the previous one, so every input is served from the render cache.
func BenchmarkCoordinator_generateComponentModel_k8sVarsUnchanged(b *testing.B) {
	benchmarkK8sVars(b, k8sBenchVars(b, true), nil)
}

// BenchmarkCoordinator_generateComponentModel_k8sVarsPodChurn measures the steady state of a
// cluster with pod churn: every render sees one pod replaced by a new one.
func BenchmarkCoordinator_generateComponentModel_k8sVarsPodChurn(b *testing.B) {
	vars := k8sBenchVars(b, true)
	i := 0
	benchmarkK8sVars(b, vars, func(coord *Coordinator) {
		i++
		// replace the last pod with a new one (new id, new mapping content)
		last := len(vars) - 1
		m, err := vars[last].Map()
		require.NoError(b, err)
		id := fmt.Sprintf("kubernetes-new-%d", i)
		v, err := transpiler.NewVarsWithProcessors(id, m, "kubernetes",
			[]map[string]any{{"add_fields": map[string]any{"fields": map[string]any{"id": id}, "target": "container"}}},
			mapstr.M{}, "env", "kubernetes")
		require.NoError(b, err)
		v.SetCacheKey("context;" + id)
		vars[last] = v
		coord.vars = vars
	})
}

// k8sBenchCoordinator returns a coordinator ready to generate the component model of the
// testdata policy against the given vars.
func k8sBenchCoordinator(b testing.TB, ctx context.Context, vars []*transpiler.Vars) *Coordinator {
	cfgMap := map[string]any{}
	cfgMapBytes, err := os.ReadFile("./testdata/config.yaml")
	require.NoError(b, err)
	require.NoError(b, yaml.Unmarshal(cfgMapBytes, &cfgMap))
	cfg, err := config.NewConfigFrom(cfgMap)
	require.NoError(b, err)
	cfgMap, err = cfg.ToMapStr()
	require.NoError(b, err)
	cfgAst, err := transpiler.NewAST(cfgMap)
	require.NoError(b, err)

	coord, _, _ := createCoordinator(b, ctx)
	coord.ast = cfgAst
	coord.vars = vars
	return coord
}

func benchmarkK8sVars(b *testing.B, vars []*transpiler.Vars, beforeRender func(*Coordinator)) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord := k8sBenchCoordinator(b, ctx, vars)

	require.NoError(b, coord.generateComponentModel())
	units := 0
	for _, c := range coord.componentModel {
		units += len(c.Units)
	}
	b.Logf("vars=%d components=%d units=%d rendered_inputs=%d", len(vars), len(coord.componentModel), units, len(coord.derivedConfig["inputs"].([]any)))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if beforeRender != nil {
			b.StopTimer()
			beforeRender(coord)
			b.StartTimer()
		}
		require.NoError(b, coord.generateComponentModel())
	}
}
