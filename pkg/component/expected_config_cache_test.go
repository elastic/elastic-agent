// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func testUnitConfig() map[string]interface{} {
	return map[string]interface{}{
		"id":         "unit-1",
		"type":       "filestream",
		"revision":   3,
		"use_output": "default",
		"paths":      []interface{}{"/var/log/a.log", "/var/log/b.log"},
		"data_stream": map[string]interface{}{
			"dataset": "generic",
			"type":    "logs",
		},
		"streams": []interface{}{
			map[string]interface{}{
				"id":          "stream-1",
				"data_stream": map[string]interface{}{"dataset": "a"},
				"enabled":     true,
				"ignore":      nil,
			},
		},
	}
}

func TestExpectedConfigCache(t *testing.T) {
	cache := NewExpectedConfigCache()

	first, err := cache.ExpectedConfig(testUnitConfig())
	require.NoError(t, err)
	// an identical configuration (a different map with the same content) reuses the result
	second, err := cache.ExpectedConfig(testUnitConfig())
	require.NoError(t, err)
	assert.Same(t, first, second)
	assert.Equal(t, 1, cache.Len())

	// a nested change is a different configuration
	changed := testUnitConfig()
	changed["streams"].([]interface{})[0].(map[string]interface{})["enabled"] = false
	third, err := cache.ExpectedConfig(changed)
	require.NoError(t, err)
	assert.NotSame(t, first, third)
	assert.False(t, proto.Equal(first, third))
	assert.Equal(t, 2, cache.Len())

	// the generated result is the same as without the cache
	uncached, err := ExpectedConfig(changed)
	require.NoError(t, err)
	assert.True(t, proto.Equal(uncached, third))

	// entries not used since the previous sweep are dropped
	cache.Sweep()
	assert.Equal(t, 2, cache.Len())
	_, err = cache.ExpectedConfig(changed)
	require.NoError(t, err)
	cache.Sweep()
	assert.Equal(t, 1, cache.Len())
	fourth, err := cache.ExpectedConfig(changed)
	require.NoError(t, err)
	assert.Same(t, third, fourth)

	// errors are not cached
	invalid := testUnitConfig()
	invalid["meta"] = []interface{}{"not a map"}
	_, err = cache.ExpectedConfig(invalid)
	require.Error(t, err)
	assert.Equal(t, 1, cache.Len())

	// the zero value is usable
	var zero ExpectedConfigCache
	_, err = zero.ExpectedConfig(testUnitConfig())
	require.NoError(t, err)
	assert.Equal(t, 1, zero.Len())

	// a nil cache generates every time
	var nilCache *ExpectedConfigCache
	a, err := nilCache.ExpectedConfig(testUnitConfig())
	require.NoError(t, err)
	b, err := nilCache.ExpectedConfig(testUnitConfig())
	require.NoError(t, err)
	assert.NotSame(t, a, b)
	nilCache.Sweep()
	assert.Equal(t, 0, nilCache.Len())
}

func TestStructEqualsMap(t *testing.T) {
	base := testUnitConfig()
	source, err := structpb.NewStruct(base)
	require.NoError(t, err)

	assert.True(t, structEqualsMap(source, testUnitConfig()))
	assert.False(t, structEqualsMap(nil, testUnitConfig()))

	// numbers are compared as the float64 they are converted to
	asFloat := testUnitConfig()
	asFloat["revision"] = float64(3)
	assert.True(t, structEqualsMap(source, asFloat))
	asFloat["revision"] = float64(3.5)
	assert.False(t, structEqualsMap(source, asFloat))

	cases := map[string]func(m map[string]interface{}){
		"missing key":      func(m map[string]interface{}) { delete(m, "type") },
		"extra key":        func(m map[string]interface{}) { m["extra"] = "x" },
		"different string": func(m map[string]interface{}) { m["type"] = "log" },
		"different type":   func(m map[string]interface{}) { m["type"] = 1 },
		"nil vs string":    func(m map[string]interface{}) { m["type"] = nil },
		"bool vs string":   func(m map[string]interface{}) { m["type"] = true },
		"list length":      func(m map[string]interface{}) { m["paths"] = []interface{}{"/var/log/a.log"} },
		"list element":     func(m map[string]interface{}) { m["paths"] = []interface{}{"/var/log/a.log", "/var/log/c.log"} },
		"list vs map":      func(m map[string]interface{}) { m["paths"] = map[string]interface{}{} },
		"nested value":     func(m map[string]interface{}) { m["data_stream"].(map[string]interface{})["dataset"] = "other" },
		"nested in list": func(m map[string]interface{}) {
			m["streams"].([]interface{})[0].(map[string]interface{})["enabled"] = false
		},
		"nil in list changed": func(m map[string]interface{}) {
			m["streams"].([]interface{})[0].(map[string]interface{})["ignore"] = ""
		},
		"unsupported type": func(m map[string]interface{}) { m["type"] = struct{}{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := testUnitConfig()
			mutate(m)
			assert.False(t, structEqualsMap(source, m))
			// the hash of a different configuration is (almost always) different too
			assert.NotEqual(t, hashConfigValue(base), hashConfigValue(m))
		})
	}
}

func TestHashConfigValueIsOrderIndependent(t *testing.T) {
	a := map[string]interface{}{"x": 1, "y": []interface{}{"a", map[string]interface{}{"k": true, "j": nil}}}
	b := map[string]interface{}{"y": []interface{}{"a", map[string]interface{}{"j": nil, "k": true}}, "x": 1}
	assert.Equal(t, hashConfigValue(a), hashConfigValue(b))
	// list order matters
	c := map[string]interface{}{"x": 1, "y": []interface{}{map[string]interface{}{"k": true, "j": nil}, "a"}}
	assert.NotEqual(t, hashConfigValue(a), hashConfigValue(c))
}

func TestExpectedConfigDecoding(t *testing.T) {
	t.Run("weakly typed scalars and case-insensitive keys", func(t *testing.T) {
		cfg := map[string]interface{}{
			"ID":       "unit-1",
			"Type":     123,
			"name":     true,
			"revision": "0x10",
		}
		got, err := ExpectedConfig(cfg)
		require.NoError(t, err)
		assert.Equal(t, "unit-1", got.Id)
		assert.Equal(t, "123", got.Type)
		assert.Equal(t, "1", got.Name)
		assert.Equal(t, uint64(16), got.Revision)

		cfg["revision"] = float64(2)
		got, err = ExpectedConfig(cfg)
		require.NoError(t, err)
		assert.Equal(t, uint64(2), got.Revision)

		cfg["revision"] = "not a number"
		_, err = ExpectedConfig(cfg)
		require.ErrorContains(t, err, "cannot parse 'revision' as uint")

		cfg["revision"] = -1
		_, err = ExpectedConfig(cfg)
		require.ErrorContains(t, err, "overflows uint")

		cfg["revision"] = 1
		cfg["type"] = map[string]interface{}{}
		_, err = ExpectedConfig(cfg)
		require.ErrorContains(t, err, "'type' expected type 'string'")
	})

	t.Run("streams", func(t *testing.T) {
		// a single map becomes a list of one stream
		cfg := map[string]interface{}{
			"id":      "unit-1",
			"streams": map[string]interface{}{"id": "only"},
		}
		got, err := ExpectedConfig(cfg)
		require.NoError(t, err)
		require.Len(t, got.Streams, 1)
		assert.Equal(t, "only", got.Streams[0].Id)

		cfg["streams"] = "nope"
		_, err = ExpectedConfig(cfg)
		require.ErrorContains(t, err, "'streams' expected a slice")

		cfg["streams"] = []interface{}{"nope"}
		_, err = ExpectedConfig(cfg)
		require.ErrorContains(t, err, "'streams[0]' expected a map or struct")

		// a null element is an error, not a crash
		cfg["streams"] = []interface{}{nil}
		_, err = ExpectedConfig(cfg)
		require.ErrorContains(t, err, "'streams[0]' expected a map or struct, got \"nil\"")

		// an empty map is no streams at all
		cfg["streams"] = map[string]interface{}{}
		got, err = ExpectedConfig(cfg)
		require.NoError(t, err)
		assert.Empty(t, got.Streams)

		// flattened data_stream keys are merged whatever form the streams take
		cfg["Streams"] = map[string]interface{}{"id": "s", "data_stream.dataset": "ds"}
		delete(cfg, "streams")
		got, err = ExpectedConfig(cfg)
		require.NoError(t, err)
		require.Len(t, got.Streams, 1)
		assert.Equal(t, "ds", got.Streams[0].DataStream.Dataset)
		assert.Same(t, got.Source.Fields["Streams"].GetStructValue(), got.Streams[0].Source)
	})

	t.Run("json.Number is accepted like structpb does", func(t *testing.T) {
		cfg := map[string]interface{}{"id": json.Number("5"), "revision": json.Number("3")}
		got, err := ExpectedConfig(cfg)
		require.NoError(t, err)
		assert.Equal(t, "5", got.Id)
		assert.Equal(t, uint64(3), got.Revision)
		assert.Equal(t, float64(3), got.Source.Fields["revision"].GetNumberValue())
	})

	t.Run("nested sources are the matching parts of the unit source", func(t *testing.T) {
		got, err := ExpectedConfig(testUnitConfig())
		require.NoError(t, err)
		streams := got.Source.Fields["streams"].GetListValue().GetValues()
		require.Len(t, streams, len(got.Streams))
		for i, stream := range got.Streams {
			assert.Same(t, stream.Source, streams[i].GetStructValue())
			assert.Same(t, stream.DataStream.Source, streams[i].GetStructValue().Fields["data_stream"].GetStructValue())
		}
		assert.Same(t, got.DataStream.Source, got.Source.Fields["data_stream"].GetStructValue())
		// and the result is what the generic conversion produces
		expected, err := structpb.NewStruct(testUnitConfig())
		require.NoError(t, err)
		assert.True(t, proto.Equal(expected, got.Source))
	})

	t.Run("unsupported values are rejected like structpb does", func(t *testing.T) {
		cfg := testUnitConfig()
		cfg["bad"] = map[string]string{"k": "v"}
		_, err := ExpectedConfig(cfg)
		require.ErrorContains(t, err, "invalid type: map[string]string")

		cfg = testUnitConfig()
		cfg["bad"] = "\xff"
		_, err = ExpectedConfig(cfg)
		require.ErrorContains(t, err, "invalid UTF-8")
	})

	t.Run("meta and package", func(t *testing.T) {
		cfg := map[string]interface{}{
			"meta": map[string]interface{}{
				"package": map[string]interface{}{"name": "system", "version": 1.2},
			},
		}
		got, err := ExpectedConfig(cfg)
		require.NoError(t, err)
		assert.Equal(t, "system", got.Meta.Package.Name)
		assert.Equal(t, "1.2", got.Meta.Package.Version)
		assert.NotNil(t, got.Meta.Source)
		assert.NotNil(t, got.Meta.Package.Source)

		cfg["meta"].(map[string]interface{})["package"] = "nope"
		_, err = ExpectedConfig(cfg)
		require.ErrorContains(t, err, "'meta.package' expected a map or struct")
	})
}
