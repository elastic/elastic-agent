// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestSettings_handleLogLevel(t *testing.T) {
	expectLogLevelApplied := func(override string, runtime logp.Level) func(*testing.T, *info.MockAgent, *info.MockAgentInfoStore, *mockLogLevelSetter, *acker.MockAcker) {
		return func(t *testing.T, agent *info.MockAgent, store *info.MockAgentInfoStore, setter *mockLogLevelSetter, acker *acker.MockAcker) {
			assertSavesLogLevelOverride(t, store, override).Return(nil)
			agent.EXPECT().SetLogLevelOverride(override)
			acker.EXPECT().Ack(mock.Anything, mock.Anything).Return(nil)
			acker.EXPECT().Commit(mock.Anything).Return(nil)
			agent.EXPECT().GetLogLevelRuntime().Return(runtime.String())
			setter.EXPECT().SetLogLevel(mock.Anything, &runtime).Return(nil)
		}
	}

	type args struct {
		logLevel string
		action   *fleetapi.ActionSettings
	}
	tests := []struct {
		name       string
		args       args
		setupMocks func(*testing.T, *info.MockAgent, *info.MockAgentInfoStore, *mockLogLevelSetter, *acker.MockAcker)
		wantErr    assert.ErrorAssertionFunc
	}{
		{
			name: "Set log level, runtime follows override",
			args: args{
				logLevel: "debug",
				action: &fleetapi.ActionSettings{
					ActionID:   "someactionid",
					ActionType: fleetapi.ActionTypeSettings,
					Data:       fleetapi.ActionSettingsData{LogLevel: "debug"},
				},
			},
			setupMocks: expectLogLevelApplied("debug", logp.DebugLevel),
			wantErr:    assert.NoError,
		},
		{
			name: "Clear log level, runtime falls back to policy level",
			args: args{
				logLevel: clearLogLevelValue,
				action: &fleetapi.ActionSettings{
					ActionID:   "someactionid",
					ActionType: fleetapi.ActionTypeSettings,
					Data:       fleetapi.ActionSettingsData{LogLevel: clearLogLevelValue},
				},
			},
			setupMocks: expectLogLevelApplied(clearLogLevelValue, logp.WarnLevel),
			wantErr:    assert.NoError,
		},
		{
			name: "Clear log level with no policy level, runtime falls back to default",
			args: args{
				logLevel: clearLogLevelValue,
				action: &fleetapi.ActionSettings{
					ActionID:   "someactionid",
					ActionType: fleetapi.ActionTypeSettings,
					Data:       fleetapi.ActionSettingsData{LogLevel: clearLogLevelValue},
				},
			},
			setupMocks: expectLogLevelApplied(clearLogLevelValue, logger.DefaultLogLevel),
			wantErr:    assert.NoError,
		},
		{
			name: "Invalid log level rejected before any state change",
			args: args{
				logLevel: "verbose",
				action: &fleetapi.ActionSettings{
					ActionID:   "someactionid",
					ActionType: fleetapi.ActionTypeSettings,
					Data:       fleetapi.ActionSettingsData{LogLevel: "verbose"},
				},
			},
			setupMocks: func(t *testing.T, agent *info.MockAgent, store *info.MockAgentInfoStore, setter *mockLogLevelSetter, acker *acker.MockAcker) {
				// no calls expected: validation fails before SetLogLevelOverride / acker / setter
			},
			wantErr: assert.Error,
		},
		{
			name: "Persistence failure surfaces as error",
			args: args{
				logLevel: "debug",
				action: &fleetapi.ActionSettings{
					ActionID:   "someactionid",
					ActionType: fleetapi.ActionTypeSettings,
					Data:       fleetapi.ActionSettingsData{LogLevel: "debug"},
				},
			},
			setupMocks: func(t *testing.T, agent *info.MockAgent, store *info.MockAgentInfoStore, setter *mockLogLevelSetter, acker *acker.MockAcker) {
				store.EXPECT().Save(mock.Anything, mock.Anything).Return(fmt.Errorf("disk write failed"))
			},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := loggertest.New(tt.name)
			mockAgentInfo := info.NewMockAgent(t)
			mockAgentInfoStore := info.NewMockAgentInfoStore(t)
			mockLogLevelSetter := newMockLogLevelSetter(t)
			mockAcker := acker.NewMockAcker(t)

			if tt.setupMocks != nil {
				tt.setupMocks(t, mockAgentInfo, mockAgentInfoStore, mockLogLevelSetter, mockAcker)
			}

			ctx := context.Background()

			h := &SettingsHandler{
				log:                   log,
				agentInfoCache:        mockAgentInfo,
				agentInfoStore:        mockAgentInfoStore,
				runtimeLogLevelSetter: mockLogLevelSetter,
			}
			tt.wantErr(t, h.handleLogLevel(ctx, tt.args.logLevel, mockAcker, tt.args.action), fmt.Sprintf("handleLogLevel(%v, %v, %v, %v)", ctx, tt.args.logLevel, mockAcker, tt.args.action))
		})
	}
}

// assertSavesLogLevelOverride returns a Save expectation that checks the
// per-agent log level override is persisted with the expected value or
// cleared when the expected value is empty.
func assertSavesLogLevelOverride(t *testing.T, store *info.MockAgentInfoStore, wantLevel string) *info.MockAgentInfoStore_Save_Call {
	return store.EXPECT().
		Save(mock.Anything, mock.Anything).
		Run(func(ctx context.Context, opts ...info.SaveOption) {
			m := map[string]any{}
			for _, o := range opts {
				o(m)
			}
			agent, _ := m["agent"].(map[string]any)
			logging, _ := agent["logging"].(map[string]any)
			if wantLevel == "" {
				_, present := logging["level_override"]
				assert.False(t, present, "WithLogLevelOverride(\"\") should not set agent.logging.level_override")
				return
			}
			assert.Equal(t, wantLevel, logging["level_override"], "WithLogLevelOverride should set agent.logging.level_override")
		})
}
