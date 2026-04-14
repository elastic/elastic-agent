// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
)

func TestServiceExtensionsList(t *testing.T) {
	t.Run("not set returns nil", func(t *testing.T) {
		cfg := confmap.New()
		assert.Nil(t, serviceExtensionsList(cfg))
	})

	t.Run("empty list", func(t *testing.T) {
		cfg := confmap.NewFromStringMap(map[string]any{
			"service": map[string]any{
				"extensions": []any{},
			},
		})
		list := serviceExtensionsList(cfg)
		assert.NotNil(t, list)
		assert.Empty(t, list)
	})

	t.Run("populated list", func(t *testing.T) {
		cfg := confmap.NewFromStringMap(map[string]any{
			"service": map[string]any{
				"extensions": []any{"ext_a", "ext_b"},
			},
		})
		list := serviceExtensionsList(cfg)
		assert.Equal(t, []interface{}{"ext_a", "ext_b"}, list)
	})

	t.Run("returns a copy, not a reference", func(t *testing.T) {
		cfg := confmap.NewFromStringMap(map[string]any{
			"service": map[string]any{
				"extensions": []any{"ext_a"},
			},
		})
		list := serviceExtensionsList(cfg)
		list[0] = "mutated"
		// Original config must be unchanged.
		assert.Equal(t, []interface{}{"ext_a"}, serviceExtensionsList(cfg))
	})
}

func TestMergeWithExtensions(t *testing.T) {
	makeConf := func(data map[string]any) *confmap.Conf {
		return confmap.NewFromStringMap(data)
	}

	t.Run("no-op when neither side has extensions", func(t *testing.T) {
		dst := makeConf(map[string]any{"receivers": map[string]any{"nop": nil}})
		src := makeConf(map[string]any{"exporters": map[string]any{"nop": nil}})
		require.NoError(t, mergeWithExtensions(dst, src))
		assert.Nil(t, serviceExtensionsList(dst))
	})

	t.Run("dst extensions preserved when src has none", func(t *testing.T) {
		dst := makeConf(map[string]any{
			"service": map[string]any{"extensions": []any{"ext_a"}},
		})
		src := makeConf(map[string]any{"receivers": map[string]any{"nop": nil}})
		require.NoError(t, mergeWithExtensions(dst, src))
		assert.Equal(t, []interface{}{"ext_a"}, serviceExtensionsList(dst))
	})

	t.Run("src extensions adopted when dst has none", func(t *testing.T) {
		dst := makeConf(map[string]any{"receivers": map[string]any{"nop": nil}})
		src := makeConf(map[string]any{
			"service": map[string]any{"extensions": []any{"ext_b"}},
		})
		require.NoError(t, mergeWithExtensions(dst, src))
		assert.Equal(t, []interface{}{"ext_b"}, serviceExtensionsList(dst))
	})

	t.Run("union when both sides have extensions", func(t *testing.T) {
		dst := makeConf(map[string]any{
			"service": map[string]any{"extensions": []any{"ext_a", "shared"}},
		})
		src := makeConf(map[string]any{
			"service": map[string]any{"extensions": []any{"ext_b", "shared"}},
		})
		require.NoError(t, mergeWithExtensions(dst, src))
		list := serviceExtensionsList(dst)
		assert.Len(t, list, 3)
		assert.Contains(t, list, "ext_a")
		assert.Contains(t, list, "ext_b")
		assert.Contains(t, list, "shared")
	})

	t.Run("dst entries appear before src-only entries", func(t *testing.T) {
		dst := makeConf(map[string]any{
			"service": map[string]any{"extensions": []any{"first", "second"}},
		})
		src := makeConf(map[string]any{
			"service": map[string]any{"extensions": []any{"third"}},
		})
		require.NoError(t, mergeWithExtensions(dst, src))
		list := serviceExtensionsList(dst)
		require.Len(t, list, 3)
		assert.Equal(t, "first", list[0])
		assert.Equal(t, "second", list[1])
		assert.Equal(t, "third", list[2])
	})

	t.Run("no-op when all src entries already in dst", func(t *testing.T) {
		dst := makeConf(map[string]any{
			"service": map[string]any{"extensions": []any{"ext_a", "ext_b"}},
		})
		src := makeConf(map[string]any{
			"service": map[string]any{"extensions": []any{"ext_a", "ext_b"}},
		})
		require.NoError(t, mergeWithExtensions(dst, src))
		assert.Equal(t, []interface{}{"ext_a", "ext_b"}, serviceExtensionsList(dst))
	})

	t.Run("other keys merged normally", func(t *testing.T) {
		dst := makeConf(map[string]any{
			"receivers": map[string]any{"r1": map[string]any{}},
			"service":   map[string]any{"extensions": []any{"ext_a"}},
		})
		src := makeConf(map[string]any{
			"exporters": map[string]any{"e1": map[string]any{}},
			"service":   map[string]any{"extensions": []any{"ext_b"}},
		})
		require.NoError(t, mergeWithExtensions(dst, src))
		assert.True(t, dst.IsSet("receivers::r1"))
		assert.True(t, dst.IsSet("exporters::e1"))
		list := serviceExtensionsList(dst)
		assert.Len(t, list, 2)
		assert.Contains(t, list, "ext_a")
		assert.Contains(t, list, "ext_b")
	})
}
