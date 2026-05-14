// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"testing"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componentstatus"
)

func TestComponentHealthToAggregate(t *testing.T) {
	t.Run("nil_returns_nil", func(t *testing.T) {
		assert.Nil(t, componentHealthToAggregate(nil))
	})

	t.Run("leaf_with_status_and_error", func(t *testing.T) {
		ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		h := &protobufs.ComponentHealth{
			Healthy:   false,
			Status:    "StatusRecoverableError",
			LastError: "something failed",
			StatusTimeUnixNano: uint64(ts.UnixNano()),
		}

		agg := componentHealthToAggregate(h)
		require.NotNil(t, agg)
		assert.Equal(t, componentstatus.StatusRecoverableError, agg.Status())
		require.Error(t, agg.Err())
		assert.Equal(t, "something failed", agg.Err().Error())
		assert.True(t, agg.Timestamp().Equal(ts))
		assert.Empty(t, agg.ComponentStatusMap)
		assert.Equal(t, 0, agg.Attributes().Len())
	})

	t.Run("ok_status_no_error", func(t *testing.T) {
		h := &protobufs.ComponentHealth{
			Healthy: true,
			Status:  "StatusOK",
		}
		agg := componentHealthToAggregate(h)
		require.NotNil(t, agg)
		assert.Equal(t, componentstatus.StatusOK, agg.Status())
		assert.NoError(t, agg.Err())
	})

	t.Run("nested_children", func(t *testing.T) {
		h := &protobufs.ComponentHealth{
			Status: "StatusOK",
			ComponentHealthMap: map[string]*protobufs.ComponentHealth{
				"pipeline:logs/in": {
					Status: "StatusOK",
					ComponentHealthMap: map[string]*protobufs.ComponentHealth{
						"receiver:nop": {Status: "StatusOK"},
						"exporter:nop": {Status: "StatusOK"},
					},
				},
				"extensions": {
					Status: "StatusOK",
					ComponentHealthMap: map[string]*protobufs.ComponentHealth{
						"extension:opamp/abc": {Status: "StatusOK"},
					},
				},
			},
		}

		agg := componentHealthToAggregate(h)
		require.NotNil(t, agg)
		require.Contains(t, agg.ComponentStatusMap, "pipeline:logs/in")
		pipeline := agg.ComponentStatusMap["pipeline:logs/in"]
		require.Contains(t, pipeline.ComponentStatusMap, "receiver:nop")
		require.Contains(t, pipeline.ComponentStatusMap, "exporter:nop")
		assert.Equal(t, componentstatus.StatusOK, pipeline.ComponentStatusMap["receiver:nop"].Status())

		require.Contains(t, agg.ComponentStatusMap, "extensions")
		require.Contains(t, agg.ComponentStatusMap["extensions"].ComponentStatusMap, "extension:opamp/abc")
	})

	t.Run("unknown_status_string_falls_back_to_none", func(t *testing.T) {
		h := &protobufs.ComponentHealth{Status: "StatusBogus"}
		agg := componentHealthToAggregate(h)
		require.NotNil(t, agg)
		assert.Equal(t, componentstatus.StatusNone, agg.Status())
	})

	t.Run("empty_status_string_falls_back_to_none", func(t *testing.T) {
		h := &protobufs.ComponentHealth{}
		agg := componentHealthToAggregate(h)
		require.NotNil(t, agg)
		assert.Equal(t, componentstatus.StatusNone, agg.Status())
		assert.NoError(t, agg.Err())
	})
}
