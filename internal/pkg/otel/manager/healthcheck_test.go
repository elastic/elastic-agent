// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent/internal/pkg/otel/status"
)

func TestAllComponentsStatuses(t *testing.T) {
	t.Run("successful response with valid status", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		serStatus := &status.SerializableStatus{
			SerializableEvent: &status.SerializableEvent{
				Healthy:      true,
				StatusString: "StatusOK",
				Timestamp:    now,
			},
			ComponentStatuses: map[string]*status.SerializableStatus{
				"receiver:otlp": {
					SerializableEvent: &status.SerializableEvent{
						Healthy:      true,
						StatusString: "StatusOK",
						Timestamp:    now,
					},
				},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, healthCheckHealthStatusPath, r.URL.Path)
			assert.True(t, r.URL.Query().Has("verbose"), "verbose query parameter should be present")
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(serStatus)
			require.NoError(t, err)
		}))
		defer server.Close()

		port := extractPort(t, server.URL)
		result, err := AllComponentsStatuses(context.Background(), *server.Client(), port)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, componentstatus.StatusOK, result.Status())
		assert.Contains(t, result.ComponentStatusMap, "receiver:otlp")
	})

	t.Run("successful response with error status", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		serStatus := &status.SerializableStatus{
			SerializableEvent: &status.SerializableEvent{
				Healthy:      false,
				StatusString: "StatusPermanentError",
				Error:        "connection refused",
				Timestamp:    now,
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(serStatus)
			require.NoError(t, err)
		}))
		defer server.Close()

		port := extractPort(t, server.URL)
		result, err := AllComponentsStatuses(context.Background(), *server.Client(), port)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, componentstatus.StatusPermanentError, result.Status())
		require.NotNil(t, result.Err())
		assert.Equal(t, "connection refused", result.Err().Error())
	})

	t.Run("connection refused error", func(t *testing.T) {
		// Use a port that's unlikely to be in use
		result, err := AllComponentsStatuses(context.Background(), http.Client{}, 59999)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get status")
		assert.Nil(t, result)
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not valid json"))
		}))
		defer server.Close()

		port := extractPort(t, server.URL)
		result, err := AllComponentsStatuses(context.Background(), *server.Client(), port)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal serializable status")
		assert.Nil(t, result)
	})

	t.Run("context cancelled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Delay response to allow context cancellation
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		port := extractPort(t, server.URL)
		result, err := AllComponentsStatuses(ctx, *server.Client(), port)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get status")
		assert.Nil(t, result)
	})

	t.Run("empty response body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Empty body
		}))
		defer server.Close()

		port := extractPort(t, server.URL)
		result, err := AllComponentsStatuses(context.Background(), *server.Client(), port)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal serializable status")
		assert.Nil(t, result)
	})

	t.Run("nested component statuses", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		serStatus := &status.SerializableStatus{
			SerializableEvent: &status.SerializableEvent{
				Healthy:      true,
				StatusString: "StatusOK",
				Timestamp:    now,
			},
			ComponentStatuses: map[string]*status.SerializableStatus{
				"pipeline:traces": {
					SerializableEvent: &status.SerializableEvent{
						Healthy:      true,
						StatusString: "StatusOK",
						Timestamp:    now,
					},
					ComponentStatuses: map[string]*status.SerializableStatus{
						"receiver:otlp": {
							SerializableEvent: &status.SerializableEvent{
								Healthy:      true,
								StatusString: "StatusOK",
								Timestamp:    now,
							},
						},
						"exporter:otlp": {
							SerializableEvent: &status.SerializableEvent{
								Healthy:      false,
								StatusString: "StatusRecoverableError",
								Error:        "temporary failure",
								Timestamp:    now,
							},
						},
					},
				},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(serStatus)
			require.NoError(t, err)
		}))
		defer server.Close()

		port := extractPort(t, server.URL)
		result, err := AllComponentsStatuses(context.Background(), *server.Client(), port)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, componentstatus.StatusOK, result.Status())

		pipelineStatus, ok := result.ComponentStatusMap["pipeline:traces"]
		require.True(t, ok)
		assert.Equal(t, componentstatus.StatusOK, pipelineStatus.Status())
		assert.Len(t, pipelineStatus.ComponentStatusMap, 2)

		exporterStatus, ok := pipelineStatus.ComponentStatusMap["exporter:otlp"]
		require.True(t, ok)
		assert.Equal(t, componentstatus.StatusRecoverableError, exporterStatus.Status())
		require.NotNil(t, exporterStatus.Err())
		assert.Equal(t, "temporary failure", exporterStatus.Err().Error())
	})
}

// extractPort extracts the port number from a URL string like "http://127.0.0.1:12345"
func extractPort(t *testing.T, url string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(url[len("http://"):])
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return port
}

func TestInjectHealthCheckV2Extension(t *testing.T) {
	const testExtensionID = "healthcheckv2/test"
	const testPort = 12345

	t.Run("injects extension config into empty config", func(t *testing.T) {
		conf := confmap.New()

		err := injectHealthCheckV2Extension(conf, testExtensionID, testPort)

		require.NoError(t, err)

		// Verify extension was added
		extConf, err := conf.Sub("extensions")
		require.NoError(t, err)
		extHealthCheck, err := extConf.Sub(testExtensionID)
		require.NoError(t, err)

		assert.Equal(t, true, extHealthCheck.Get("use_v2"))
		assert.Equal(t, fmt.Sprintf("localhost:%d", testPort), extHealthCheck.Get("http::endpoint"))
		assert.Equal(t, healthCheckHealthStatusPath, extHealthCheck.Get("http::status::path"))
		assert.Equal(t, healthCheckHealthStatusEnabled, extHealthCheck.Get("http::status::enabled"))
		assert.Equal(t, healthCheckHealthConfigPath, extHealthCheck.Get("http::config::path"))
		assert.Equal(t, healthCheckHealthConfigEnabled, extHealthCheck.Get("http::config::enabled"))
		assert.Equal(t, healthCheckIncludePermanentErrors, extHealthCheck.Get("component_health::include_permanent_errors"))
		assert.Equal(t, healthCheckIncludeRecoverableErrors, extHealthCheck.Get("component_health::include_recoverable_errors"))
		assert.Equal(t, healthCheckRecoveryDuration, extHealthCheck.Get("component_health::recovery_duration"))
	})

	t.Run("no service defined creates service with extension", func(t *testing.T) {
		conf := confmap.New()

		err := injectHealthCheckV2Extension(conf, testExtensionID, testPort)

		require.NoError(t, err)

		// Extension config should be present
		extConf, err := conf.Sub("extensions")
		require.NoError(t, err)
		assert.NotNil(t, extConf.Get(testExtensionID))

		// Service with extensions should be created
		serviceExtensions := conf.Get("service::extensions")
		require.NotNil(t, serviceExtensions)
		extSlice, ok := serviceExtensions.([]interface{})
		require.True(t, ok)
		assert.Contains(t, extSlice, testExtensionID)
	})

	t.Run("service without extensions adds extension to service", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]interface{}{
			"service": map[string]interface{}{
				"pipelines": map[string]interface{}{
					"traces": map[string]interface{}{
						"receivers": []string{"otlp"},
						"exporters": []string{"otlp"},
					},
				},
			},
		})

		err := injectHealthCheckV2Extension(conf, testExtensionID, testPort)

		require.NoError(t, err)

		// Verify extension was added to service
		serviceExtensions := conf.Get("service::extensions")
		require.NotNil(t, serviceExtensions)
		extSlice, ok := serviceExtensions.([]interface{})
		require.True(t, ok)
		assert.Contains(t, extSlice, testExtensionID)
	})

	t.Run("service with existing extensions appends new extension", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]interface{}{
			"extensions": map[string]interface{}{
				"zpages": map[string]interface{}{},
			},
			"service": map[string]interface{}{
				"extensions": []interface{}{"zpages"},
				"pipelines": map[string]interface{}{
					"traces": map[string]interface{}{
						"receivers": []string{"otlp"},
						"exporters": []string{"otlp"},
					},
				},
			},
		})

		err := injectHealthCheckV2Extension(conf, testExtensionID, testPort)

		require.NoError(t, err)

		// Verify both extensions are present
		serviceExtensions := conf.Get("service::extensions")
		require.NotNil(t, serviceExtensions)
		extSlice, ok := serviceExtensions.([]interface{})
		require.True(t, ok)
		assert.Len(t, extSlice, 2)
		assert.Contains(t, extSlice, "zpages")
		assert.Contains(t, extSlice, testExtensionID)
	})

	t.Run("extension already present in service is not duplicated", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]interface{}{
			"extensions": map[string]interface{}{
				testExtensionID: map[string]interface{}{},
			},
			"service": map[string]interface{}{
				"extensions": []interface{}{testExtensionID},
				"pipelines": map[string]interface{}{
					"traces": map[string]interface{}{
						"receivers": []string{"otlp"},
						"exporters": []string{"otlp"},
					},
				},
			},
		})

		err := injectHealthCheckV2Extension(conf, testExtensionID, testPort)

		require.NoError(t, err)

		// Verify extension appears only once
		serviceExtensions := conf.Get("service::extensions")
		require.NotNil(t, serviceExtensions)
		extSlice, ok := serviceExtensions.([]interface{})
		require.True(t, ok)
		assert.Len(t, extSlice, 1)
		assert.Contains(t, extSlice, testExtensionID)
	})

	t.Run("service extensions with wrong type returns error", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]interface{}{
			"service": map[string]interface{}{
				"extensions": "invalid-not-a-slice",
				"pipelines": map[string]interface{}{
					"traces": map[string]interface{}{
						"receivers": []string{"otlp"},
						"exporters": []string{"otlp"},
					},
				},
			},
		})

		err := injectHealthCheckV2Extension(conf, testExtensionID, testPort)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "merge into service::extensions failed")
		assert.Contains(t, err.Error(), "expected []interface{}")
	})

	t.Run("multiple existing extensions preserves order and appends", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]interface{}{
			"extensions": map[string]interface{}{
				"zpages": map[string]interface{}{},
				"pprof":  map[string]interface{}{},
			},
			"service": map[string]interface{}{
				"extensions": []interface{}{"zpages", "pprof"},
				"pipelines": map[string]interface{}{
					"traces": map[string]interface{}{
						"receivers": []string{"otlp"},
						"exporters": []string{"otlp"},
					},
				},
			},
		})

		err := injectHealthCheckV2Extension(conf, testExtensionID, testPort)

		require.NoError(t, err)

		serviceExtensions := conf.Get("service::extensions")
		require.NotNil(t, serviceExtensions)
		extSlice, ok := serviceExtensions.([]interface{})
		require.True(t, ok)
		assert.Len(t, extSlice, 3)
		// Verify order: existing extensions first, then new one
		assert.Equal(t, "zpages", extSlice[0])
		assert.Equal(t, "pprof", extSlice[1])
		assert.Equal(t, testExtensionID, extSlice[2])
	})
}
