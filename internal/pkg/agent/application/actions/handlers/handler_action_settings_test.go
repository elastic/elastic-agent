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
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	mockhandlers "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/agent/application/actions/handlers"
	mockinfo "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/agent/application/info"
	mockfleetacker "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/fleetapi/acker"
)

func TestSettings_SetLogLevel(t *testing.T) {

	// test log level we use in testcases
	testWarnLevel := logp.WarnLevel

	type fields struct {
		fallbackLogLevel *logp.Level
	}
	type args struct {
		lvl *logp.Level
	}
	tests := []struct {
		name                 string
		fields               fields
		args                 args
		setupMocks           func(*testing.T, *mockhandlers.LogLevelSetter, *mockinfo.Agent)
		wantErr              assert.ErrorAssertionFunc
		wantFallbackLogLevel *logp.Level
	}{
		{
			name:   "fallbackLogLevel set without an override at agent level",
			fields: fields{},
			args: args{
				lvl: &testWarnLevel,
			},
			setupMocks: func(t *testing.T, setter *mockhandlers.LogLevelSetter, agent *mockinfo.Agent) {
				agent.EXPECT().RawLogLevel().Return("").Once()
				setter.EXPECT().SetLogLevel(mock.Anything, &testWarnLevel).Return(nil).Once()
			},
			wantErr:              assert.NoError,
			wantFallbackLogLevel: &testWarnLevel,
		},
		{
			name:   "Nil fallbackLogLevel without an override at agent level is not propagated",
			fields: fields{},
			args: args{
				lvl: nil,
			},
			setupMocks: func(t *testing.T, setter *mockhandlers.LogLevelSetter, agent *mockinfo.Agent) {
				agent.EXPECT().RawLogLevel().Return("").Once()
				// we should never call the SetLogLevel with nil, for simplicity remove the expectation altogether
				// setter.EXPECT().SetLogLevel(mock.Anything, nil).Return(nil).Times(0)
			},
			wantErr:              assert.NoError,
			wantFallbackLogLevel: nil,
		},
		{
			name:   "fallbackLogLevel set while there's an override at agent level",
			fields: fields{},
			args: args{
				lvl: &testWarnLevel,
			},
			setupMocks: func(t *testing.T, setter *mockhandlers.LogLevelSetter, agent *mockinfo.Agent) {
				agent.EXPECT().RawLogLevel().Return("info").Once()
			},
			wantErr:              assert.NoError,
			wantFallbackLogLevel: &testWarnLevel,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAgentInfo := mockinfo.NewAgent(t)
			mockLogLevelSetter := mockhandlers.NewLogLevelSetter(t)

			if tt.setupMocks != nil {
				tt.setupMocks(t, mockLogLevelSetter, mockAgentInfo)
			}

			log, _ := loggertest.New(tt.name)

			ctx := context.Background()

			h := &Settings{
				log:              log,
				agentInfo:        mockAgentInfo,
				fallbackLogLevel: tt.fields.fallbackLogLevel,
				logLevelSetter:   mockLogLevelSetter,
			}
			tt.wantErr(t, h.SetLogLevel(ctx, tt.args.lvl), fmt.Sprintf("SetLogLevel(%v, %v)", ctx, tt.args.lvl))
			assert.Equal(t, tt.wantFallbackLogLevel, h.fallbackLogLevel)
		})
	}
}

func TestSettings_handleLogLevel(t *testing.T) {

	testWarnLogLevel := logp.WarnLevel
	testDebugLogLevel := logp.DebugLevel
	testDefaultLogLevel := logger.DefaultLogLevel
	type fields struct {
		fallbackLogLevel *logp.Level
	}
	type args struct {
		logLevel string
		action   *fleetapi.ActionSettings
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		setupMocks func(*testing.T, *mockinfo.Agent, *mockhandlers.LogLevelSetter, *mockfleetacker.Acker)
		wantErr    assert.ErrorAssertionFunc
	}{
		{
			name: "Set debug log level, disregard fallback level warning",
			fields: fields{
				fallbackLogLevel: &testWarnLogLevel,
			},
			args: args{
				logLevel: "debug",
				action: &fleetapi.ActionSettings{
					ActionID:   "someactionid",
					ActionType: fleetapi.ActionTypeSettings,
					Data:       fleetapi.ActionSettingsData{LogLevel: "debug"},
				},
			},
			setupMocks: func(t *testing.T, agent *mockinfo.Agent, setter *mockhandlers.LogLevelSetter, acker *mockfleetacker.Acker) {
				agent.EXPECT().SetLogLevel(mock.Anything, "debug").Return(nil)
				setter.EXPECT().SetLogLevel(mock.Anything, &testDebugLogLevel).Return(nil)
				acker.EXPECT().Ack(mock.Anything, mock.Anything).Return(nil)
				acker.EXPECT().Commit(mock.Anything).Return(nil)
			},
			wantErr: assert.NoError,
		},
		{
			name: "Clear log level, switch to fallback level warning",
			fields: fields{
				fallbackLogLevel: &testWarnLogLevel,
			},
			args: args{
				logLevel: clearLogLevelValue,
				action: &fleetapi.ActionSettings{
					ActionID:   "someactionid",
					ActionType: fleetapi.ActionTypeSettings,
					Data: fleetapi.ActionSettingsData{
						LogLevel: clearLogLevelValue},
				},
			},
			setupMocks: func(t *testing.T, agent *mockinfo.Agent, setter *mockhandlers.LogLevelSetter, acker *mockfleetacker.Acker) {
				agent.EXPECT().SetLogLevel(mock.Anything, "").Return(nil)
				setter.EXPECT().SetLogLevel(mock.Anything, &testWarnLogLevel).Return(nil)
				acker.EXPECT().Ack(mock.Anything, mock.Anything).Return(nil)
				acker.EXPECT().Commit(mock.Anything).Return(nil)
			},
			wantErr: assert.NoError,
		},
		{
			name: "Clear log level, no fallback level, go with default log level",
			fields: fields{
				fallbackLogLevel: nil,
			},
			args: args{
				logLevel: clearLogLevelValue,
				action: &fleetapi.ActionSettings{
					ActionID:   "someactionid",
					ActionType: fleetapi.ActionTypeSettings,
					Data: fleetapi.ActionSettingsData{
						LogLevel: clearLogLevelValue},
				},
			},
			setupMocks: func(t *testing.T, agent *mockinfo.Agent, setter *mockhandlers.LogLevelSetter, acker *mockfleetacker.Acker) {
				agent.EXPECT().SetLogLevel(mock.Anything, "").Return(nil)
				setter.EXPECT().SetLogLevel(mock.Anything, &testDefaultLogLevel).Return(nil)
				acker.EXPECT().Ack(mock.Anything, mock.Anything).Return(nil)
				acker.EXPECT().Commit(mock.Anything).Return(nil)
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := loggertest.New(tt.name)
			mockAgentInfo := mockinfo.NewAgent(t)
			mockLogLevelSetter := mockhandlers.NewLogLevelSetter(t)
			mockAcker := mockfleetacker.NewAcker(t)

			if tt.setupMocks != nil {
				tt.setupMocks(t, mockAgentInfo, mockLogLevelSetter, mockAcker)
			}

			ctx := context.Background()

			h := &Settings{
				log:              log,
				agentInfo:        mockAgentInfo,
				fallbackLogLevel: tt.fields.fallbackLogLevel,
				logLevelSetter:   mockLogLevelSetter,
			}
			tt.wantErr(t, h.handleLogLevel(ctx, tt.args.logLevel, mockAcker, tt.args.action), fmt.Sprintf("handleLogLevel(%v, %v, %v, %v)", ctx, tt.args.logLevel, mockAcker, tt.args.action))
		})
	}
}
