// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/component"
)

func TestAddToBucket(t *testing.T) {
	testCases := map[string]struct {
		bucketSize int
		dropRate   time.Duration
		add        int
		// Warning: this sleep duration is not very precise on Windows machines as the system clock ticks only every 15ms
		addSleep    time.Duration
		shouldBlock bool
	}{
		"no error":           {1, 50 * time.Millisecond, 0, 1 * time.Millisecond, false},
		"error within limit": {1, 50 * time.Millisecond, 1, 1 * time.Millisecond, false},
		"errors > than limit but across timespans":                {1, 50 * time.Millisecond, 2, 80 * time.Millisecond, false},
		"errors > than limit within timespans, exact bucket size": {2, 50 * time.Millisecond, 2, 2 * time.Millisecond, false},
		// These testcases use a longer duration as dropRate to make sure that on Windows machine we don't drop any old events
		"errors > than limit within timespans, off by one": {2, 150 * time.Millisecond, 3, 2 * time.Millisecond, true},
		"errors > than limit within timespans":             {2, 150 * time.Millisecond, 4, 2 * time.Millisecond, true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("https://github.com/elastic/elastic-agent/issues/3290: Flaky timing on Windows")
			}
			b := newRateLimiter(tc.dropRate, tc.bucketSize)

			blocked := false
			b.Allow()
			<-time.After(tc.dropRate + 20*time.Millisecond) // init ticker

			for i := 0; i < tc.add; i++ {
				t.Logf("%v : add 1 element when there are %f tokens available", time.Now(), b.Tokens())
				wasBlocked := !b.Allow()
				blocked = blocked || wasBlocked
				<-time.After(tc.addSleep)
			}
			require.Equal(t, tc.shouldBlock, blocked)
		})
	}
}

// TestSyncExpected verifies that the command runtime correctly establish if we need to send a CheckinObserved after an
// update in the model coming from the coordinator
func TestSyncExpected(t *testing.T) {

	tenPercentSamplingRate := float32(0.1)
	anotherTenPercentSamplingRate := tenPercentSamplingRate
	t.Run("TestAPMConfig", func(t *testing.T) {
		testcases := []struct {
			name          string
			initialConfig *proto.APMConfig
			updatedConfig *proto.APMConfig
			syncExpected  bool
		}{
			{
				name:          "No config (both nil)",
				initialConfig: nil,
				updatedConfig: nil,
				syncExpected:  false,
			},
			{
				name:          "Config added",
				initialConfig: nil,
				updatedConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment: "test",
						ApiKey:      "apikey",
						Hosts:       []string{"some.somedomain"},
					},
				},
				syncExpected: true,
			},
			{
				name: "Same config",
				initialConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment: "test",
						ApiKey:      "apikey",
						Hosts:       []string{"some.somedomain"},
					},
				},
				updatedConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment: "test",
						ApiKey:      "apikey",
						Hosts:       []string{"some.somedomain"},
					},
				},
				syncExpected: false,
			},
			{
				name: "Added sampling rate",
				initialConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment: "test",
						ApiKey:      "apikey",
						Hosts:       []string{"some.somedomain"},
					},
				},
				updatedConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment:  "test",
						ApiKey:       "apikey",
						Hosts:        []string{"some.somedomain"},
						SamplingRate: &tenPercentSamplingRate,
					},
				},
				syncExpected: true,
			},
			{
				name: "Same sampling rate",
				initialConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment:  "test",
						ApiKey:       "apikey",
						Hosts:        []string{"some.somedomain"},
						SamplingRate: &tenPercentSamplingRate,
					},
				},
				updatedConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment:  "test",
						ApiKey:       "apikey",
						Hosts:        []string{"some.somedomain"},
						SamplingRate: &anotherTenPercentSamplingRate,
					},
				},
				syncExpected: false,
			},
			{
				name: "Remove sampling rate",
				initialConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment:  "test",
						ApiKey:       "apikey",
						Hosts:        []string{"some.somedomain"},
						SamplingRate: &tenPercentSamplingRate,
					},
				},
				updatedConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment: "test",
						ApiKey:      "apikey",
						Hosts:       []string{"some.somedomain"},
					},
				},
				syncExpected: true,
			},
		}

		for _, tt := range testcases {
			t.Run(tt.name, func(t *testing.T) {
				compState := ComponentState{
					State:       client.UnitStateHealthy,
					Message:     "fake component state running",
					Features:    nil,
					FeaturesIdx: 0,
					Component: &proto.Component{
						ApmConfig: tt.initialConfig,
					},
					ComponentIdx: 0,
					VersionInfo: ComponentVersionInfo{
						Name:      "fake component",
						BuildHash: "abcdefgh",
					},
					Pid:                 123,
					expectedUnits:       nil,
					expectedFeatures:    nil,
					expectedFeaturesIdx: 0,
					expectedComponent: &proto.Component{
						ApmConfig: tt.initialConfig,
					},
					expectedComponentIdx: 0,
				}

				actualSyncExpected := compState.syncExpected(&component.Component{
					ID: "fakecomponent",
					Component: &proto.Component{
						ApmConfig: tt.updatedConfig,
					},
				})

				assert.Equal(t, tt.syncExpected, actualSyncExpected)
			})
		}
	})

}

func TestCreateLogWriterJSONEncoder(t *testing.T) {
	componentType := "test-type"
	componentBinary := "test-binary"
	expectedDataset := "elastic_agent.test_binary"
	expectedMessage := "hello"
	expectedLogLevel := "info"

	testCases := []struct {
		name                 string
		componentID          string
		makeEvent            func(cmdSpec *component.CommandSpec) map[string]any
		logSource            logSource
		expectLogObjectField bool
	}{
		{
			name:        "adds log.source without overwriting log map",
			componentID: "component-id",
			makeEvent: func(cmdSpec *component.CommandSpec) map[string]any {
				return map[string]any{
					"@timestamp": time.Now().UTC().Format(cmdSpec.Log.TimeFormat),
					"message":    expectedMessage,
					"log.level":  expectedLogLevel,
					"log": map[string]any{
						"logger": "subprocess",
						"path":   "subprocess-path",
					},
				}
			},
			logSource:            logSourceStdout,
			expectLogObjectField: true,
		},
		{
			name:        "adds log.source without overwriting log map (stderr)",
			componentID: "component-id",
			makeEvent: func(cmdSpec *component.CommandSpec) map[string]any {
				return map[string]any{
					"@timestamp": time.Now().UTC().Format(cmdSpec.Log.TimeFormat),
					"message":    expectedMessage,
					"log.level":  expectedLogLevel,
					"log": map[string]any{
						"logger": "subprocess",
						"path":   "subprocess-path",
					},
				}
			},
			logSource:            logSourceStderr,
			expectLogObjectField: true,
		},
		{
			name:        "adds log.source when log map is missing",
			componentID: "component-id",
			makeEvent: func(cmdSpec *component.CommandSpec) map[string]any {
				return map[string]any{
					"@timestamp": time.Now().UTC().Format(cmdSpec.Log.TimeFormat),
					"message":    expectedMessage,
					"log.level":  expectedLogLevel,
				}
			},
			logSource:            logSourceStdout,
			expectLogObjectField: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup logger/encoder
			var buf bytes.Buffer
			encoderConfig := ecszap.ECSCompatibleEncoderConfig(logp.JSONEncoderConfig())
			core := zapcore.NewCore(
				zapcore.NewJSONEncoder(encoderConfig),
				zapcore.AddSync(&buf),
				zapcore.DebugLevel,
			)
			log := logp.NewLogger(
				"test",
				zap.WrapCore(func(in zapcore.Core) zapcore.Core {
					return core
				}),
			)

			// Setup command spec + writer
			cmdSpec := &component.CommandSpec{}
			cmdSpec.Log.InitDefaults()

			logWriter := createLogWriter(
				component.Component{ID: tc.componentID},
				log,
				cmdSpec,
				componentType,
				componentBinary,
				zapcore.InfoLevel,
				nil,
				tc.logSource,
			)

			// Emit log line
			event := tc.makeEvent(cmdSpec)
			payload, err := json.Marshal(event)
			require.NoError(t, err)

			_, err = logWriter.Write(append(payload, '\n'))
			require.NoError(t, err)

			// Collect output.
			output := strings.TrimSpace(buf.String())
			require.NotEmpty(t, output)

			lines := strings.Split(output, "\n")
			require.Len(t, lines, 1)

			// Decode JSON line for field assertions
			var logged map[string]any
			require.NoError(t, json.Unmarshal([]byte(lines[0]), &logged))

			// Assert core component log fields
			require.Equal(t, expectedMessage, logged["message"])
			require.Equal(t, expectedLogLevel, logged["log.level"])
			if tc.expectLogObjectField {
				logValue, ok := logged["log"].(map[string]any)
				require.True(t, ok)
				require.Equal(t, "subprocess", logValue["logger"])
				require.Equal(t, "subprocess-path", logValue["path"])
			} else {
				_, hasLog := logged["log"]
				require.False(t, hasLog)
			}

			// Assert added fields
			require.Equal(t, tc.componentID, logged["component.id"])
			require.Equal(t, componentType, logged["component.type"])
			require.Equal(t, componentBinary, logged["component.binary"])
			require.Equal(t, expectedDataset, logged["component.dataset"])
			require.Equal(t, tc.componentID, logged["log.source"])
		})
	}
}
