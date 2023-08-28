// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions/handlers/mocks"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

//go:generate mockery --name Uploader
//go:generate mockery --name diagnosticsProvider --exported
//go:generate mockery --dir ../../../../fleetapi/acker --name Acker

var defaultRateLimit config.Limit = config.Limit{
	Interval: 1 * time.Millisecond,
	Burst:    10,
}

var hook1 diagnostics.Hook = diagnostics.Hook{
	Name:        "hook1",
	Filename:    "hook1.yaml",
	ContentType: "application/yaml",
	Hook: func(ctx context.Context) []byte {
		return []byte(`hook: 1`)
	},
}

var globalHooksNameAndFiles map[string]string

func init() {
	globalHooksNameAndFiles = map[string]string{}
	for _, gh := range diagnostics.GlobalHooks() {
		globalHooksNameAndFiles[gh.Name] = gh.Filename
	}
}

var (
	mockInputUnit      = component.Unit{ID: "UnitID", Type: client.UnitTypeInput}
	mockUnitDiagnostic = runtime.ComponentUnitDiagnostic{
		Component: component.Component{
			ID:    "ComponentID",
			Units: []component.Unit{mockInputUnit},
		},
		Unit: mockInputUnit,
		Results: []*proto.ActionDiagnosticUnitResult{
			{
				Name:        "mock unit diagnostic result",
				Filename:    "mock_unit_diag_file.yaml",
				ContentType: "application/yaml",
				Content:     []byte("hello: there"),
			},
		},
	}
)

func TestDiagnosticHandlerHappyPathWithLogs(t *testing.T) {

	tempAgentRoot := t.TempDir()
	paths.SetTop(tempAgentRoot)
	err := os.MkdirAll(path.Join(tempAgentRoot, "data"), 0755)
	require.NoError(t, err)

	mockDiagProvider := mocks.NewDiagnosticsProvider(t)
	mockUploader := mocks.NewUploader(t)
	testLogger, observedLogs := logger.NewTesting("diagnostic-handler-test")
	handler := NewDiagnostics(testLogger, mockDiagProvider, defaultRateLimit, mockUploader)

	mockDiagProvider.EXPECT().DiagnosticHooks().Return([]diagnostics.Hook{hook1})
	mockDiagProvider.EXPECT().PerformDiagnostics(mock.Anything, mock.Anything).Return([]runtime.ComponentUnitDiagnostic{mockUnitDiagnostic})
	mockDiagProvider.EXPECT().PerformComponentDiagnostics(mock.Anything, mock.Anything).Return([]runtime.ComponentDiagnostic{}, nil)

	mockAcker := mocks.NewAcker(t)
	mockAcker.EXPECT().Ack(mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, a fleetapi.Action) error {
		require.IsType(t, new(fleetapi.ActionDiagnostics), a)
		assert.NoError(t, a.(*fleetapi.ActionDiagnostics).Err)
		return nil
	})
	mockAcker.EXPECT().Commit(mock.Anything).Return(nil)

	mockUploader.EXPECT().UploadDiagnostics(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("upload-id", nil)

	diagAction := &fleetapi.ActionDiagnostics{}

	handler.collectDiag(context.Background(), diagAction, mockAcker)

	assert.Len(t, observedLogs.FilterLevelExact(zapcore.ErrorLevel).All(), 0)
	// need 2 logs for each coordinator hook (start and end)
	assert.Lenf(
		t,
		observedLogs.FilterLevelExact(zapcore.DebugLevel).
			FilterField(zapcore.Field{Key: "hook", Type: zapcore.StringType, String: hook1.Name}).
			FilterField(zapcore.Field{Key: "filename", Type: zapcore.StringType, String: hook1.Filename}).
			All(),
		2,
		"couldn't find start/end logs for hook %q file %q", hook1.Name, hook1.Filename)
	assert.Lenf(
		t,
		observedLogs.FilterLevelExact(zapcore.DebugLevel).
			FilterField(zapcore.Field{Key: "hook", Type: zapcore.StringType, String: hook1.Name}).
			FilterField(zapcore.Field{Key: "filename", Type: zapcore.StringType, String: hook1.Filename}).
			FilterFieldKey("elapsed").
			All(),
		1,
		"couldn't find end log with elapsed time for hook %q file %q", hook1.Name, hook1.Filename)

	// need 2 logs also for each global hook
	for n, f := range globalHooksNameAndFiles {
		assert.Lenf(t,
			observedLogs.FilterLevelExact(zapcore.DebugLevel).
				FilterField(zapcore.Field{Key: "hook", Type: zapcore.StringType, String: n}).
				FilterField(zapcore.Field{Key: "filename", Type: zapcore.StringType, String: f}).
				All(),
			2,
			"couldn't find start/end logs for global hook %q file %q", n, f)
		assert.Lenf(
			t,
			observedLogs.FilterLevelExact(zapcore.DebugLevel).
				FilterField(zapcore.Field{Key: "hook", Type: zapcore.StringType, String: n}).
				FilterField(zapcore.Field{Key: "filename", Type: zapcore.StringType, String: f}).
				FilterFieldKey("elapsed").
				All(),
			1,
			"couldn't find end log with elapsed time for hook %q file %q", n, f)
	}

	// need a final log with the action and  total elapsed time
	assert.Lenf(t,
		observedLogs.FilterLevelExact(zapcore.DebugLevel).
			FilterField(zapcore.Field{Key: "action", Type: zapcore.StringerType, Interface: diagAction}).
			FilterFieldKey("elapsed").All(),
		1,
		"couldn't find final log for action that includes the elapsed time")

	// this is also checked in the Ack() mock call
	assert.NoError(t, diagAction.Err)
}

func TestDiagnosticHandlerUploaderErrorWithLogs(t *testing.T) {
	tempAgentRoot := t.TempDir()
	paths.SetTop(tempAgentRoot)
	err := os.MkdirAll(path.Join(tempAgentRoot, "data"), 0755)
	require.NoError(t, err)

	mockDiagProvider := mocks.NewDiagnosticsProvider(t)
	mockUploader := mocks.NewUploader(t)
	testLogger, observedLogs := logger.NewTesting("diagnostic-handler-test")
	handler := NewDiagnostics(testLogger, mockDiagProvider, defaultRateLimit, mockUploader)

	mockDiagProvider.EXPECT().DiagnosticHooks().Return([]diagnostics.Hook{})
	mockDiagProvider.EXPECT().PerformDiagnostics(mock.Anything, mock.Anything).Return([]runtime.ComponentUnitDiagnostic{})
	mockDiagProvider.EXPECT().PerformComponentDiagnostics(mock.Anything, mock.Anything).Return([]runtime.ComponentDiagnostic{}, nil)

	// this error will be returbned by the uploader
	uploaderError := errors.New("upload went wrong!")
	mockUploader.EXPECT().UploadDiagnostics(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", uploaderError)

	mockAcker := mocks.NewAcker(t)
	mockAcker.EXPECT().Ack(mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, a fleetapi.Action) error {
		require.IsType(t, new(fleetapi.ActionDiagnostics), a)
		// verify that we are acking the action with the correct error set
		assert.ErrorIs(t, a.(*fleetapi.ActionDiagnostics).Err, uploaderError)
		return nil
	})
	mockAcker.EXPECT().Commit(mock.Anything).Return(nil)

	diagAction := &fleetapi.ActionDiagnostics{}
	handler.collectDiag(context.Background(), diagAction, mockAcker)

	// assert that we logged an ERROR log that includes the error from uploader and the action
	assert.Len(t,
		observedLogs.FilterLevelExact(zapcore.ErrorLevel).
			FilterField(zapcore.Field{Key: "error.message", Type: zapcore.ErrorType, Interface: uploaderError}).
			FilterField(zapcore.Field{Key: "action", Type: zapcore.StringerType, Interface: diagAction}).
			All(),
		1)
	// we could assert the logs for the hooks, but those will be the same as the happy path, so for brevity we won't
}

func TestDiagnosticHandlerZipArchiveErrorWithLogs(t *testing.T) {
	tempAgentRoot := t.TempDir()
	paths.SetTop(tempAgentRoot)
	// we don't set a 'data' subdirectory in order to make the zip process return an error
	// this is the only way/trick to do it with the current implementation, sadly :(

	mockDiagProvider := mocks.NewDiagnosticsProvider(t)
	mockUploader := mocks.NewUploader(t)
	testLogger, observedLogs := logger.NewTesting("diagnostic-handler-test")
	handler := NewDiagnostics(testLogger, mockDiagProvider, defaultRateLimit, mockUploader)

	mockDiagProvider.EXPECT().DiagnosticHooks().Return([]diagnostics.Hook{})
	mockDiagProvider.EXPECT().PerformDiagnostics(mock.Anything, mock.Anything).Return([]runtime.ComponentUnitDiagnostic{})
	mockDiagProvider.EXPECT().PerformComponentDiagnostics(mock.Anything, mock.Anything).Return([]runtime.ComponentDiagnostic{}, nil)

	mockAcker := mocks.NewAcker(t)
	mockAcker.EXPECT().Ack(mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, a fleetapi.Action) error {
		require.IsType(t, new(fleetapi.ActionDiagnostics), a)
		assert.Error(t, a.(*fleetapi.ActionDiagnostics).Err)
		return nil
	})
	mockAcker.EXPECT().Commit(mock.Anything).Return(nil)

	diagAction := &fleetapi.ActionDiagnostics{}
	handler.collectDiag(context.Background(), diagAction, mockAcker)

	// assert that we logged an ERROR log that includes the error from the zip compression and the action
	assert.Len(t,
		observedLogs.FilterLevelExact(zapcore.ErrorLevel).
			FilterFieldKey("error.message").
			FilterField(zapcore.Field{Key: "action", Type: zapcore.StringerType, Interface: diagAction}).
			All(),
		1)
	// we could assert the logs for the hooks, but those will be the same as the happy path, so for brevity we won't
}

func TestDiagnosticHandlerAckErrorWithLogs(t *testing.T) {
	tempAgentRoot := t.TempDir()
	paths.SetTop(tempAgentRoot)
	err := os.MkdirAll(path.Join(tempAgentRoot, "data"), 0755)
	require.NoError(t, err)

	mockDiagProvider := mocks.NewDiagnosticsProvider(t)
	mockUploader := mocks.NewUploader(t)
	testLogger, observedLogs := logger.NewTesting("diagnostic-handler-test")
	handler := NewDiagnostics(testLogger, mockDiagProvider, defaultRateLimit, mockUploader)

	mockDiagProvider.EXPECT().DiagnosticHooks().Return([]diagnostics.Hook{})
	mockDiagProvider.EXPECT().PerformDiagnostics(mock.Anything, mock.Anything).Return([]runtime.ComponentUnitDiagnostic{})
	mockDiagProvider.EXPECT().PerformComponentDiagnostics(mock.Anything, mock.Anything).Return([]runtime.ComponentDiagnostic{}, nil)

	mockAcker := mocks.NewAcker(t)
	ackError := errors.New("acking went wrong")
	mockAcker.EXPECT().Ack(mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, a fleetapi.Action) error {
		require.IsType(t, new(fleetapi.ActionDiagnostics), a)
		assert.NoError(t, a.(*fleetapi.ActionDiagnostics).Err)
		return ackError
	})
	mockAcker.EXPECT().Commit(mock.Anything).Return(nil)

	mockUploader.EXPECT().UploadDiagnostics(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("upload-id", nil)

	diagAction := &fleetapi.ActionDiagnostics{}
	handler.collectDiag(context.Background(), diagAction, mockAcker)

	// assert that we logged an ERROR log that includes the error from acker and the action
	assert.Len(t,
		observedLogs.FilterLevelExact(zapcore.ErrorLevel).
			FilterField(zapcore.Field{Key: "error.message", Type: zapcore.ErrorType, Interface: ackError}).
			FilterField(zapcore.Field{Key: "action", Type: zapcore.StringerType, Interface: diagAction}).
			All(),
		1)
	// we could assert the logs for the hooks, but those will be the same as the happy path, so for brevity we won't
}

func TestDiagnosticHandlerCommitErrorWithLogs(t *testing.T) {
	tempAgentRoot := t.TempDir()
	paths.SetTop(tempAgentRoot)
	err := os.MkdirAll(path.Join(tempAgentRoot, "data"), 0755)
	require.NoError(t, err)

	mockDiagProvider := mocks.NewDiagnosticsProvider(t)
	mockUploader := mocks.NewUploader(t)
	testLogger, observedLogs := logger.NewTesting("diagnostic-handler-test")
	handler := NewDiagnostics(testLogger, mockDiagProvider, defaultRateLimit, mockUploader)

	mockDiagProvider.EXPECT().DiagnosticHooks().Return([]diagnostics.Hook{})
	mockDiagProvider.EXPECT().PerformDiagnostics(mock.Anything, mock.Anything).Return([]runtime.ComponentUnitDiagnostic{})
	mockDiagProvider.EXPECT().PerformComponentDiagnostics(mock.Anything, mock.Anything).Return([]runtime.ComponentDiagnostic{}, nil)

	mockAcker := mocks.NewAcker(t)
	mockAcker.EXPECT().Ack(mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, a fleetapi.Action) error {
		require.IsType(t, new(fleetapi.ActionDiagnostics), a)
		assert.NoError(t, a.(*fleetapi.ActionDiagnostics).Err)
		return nil
	})

	commitError := errors.New("commit went wrong")
	mockAcker.EXPECT().Commit(mock.Anything).Return(commitError)

	mockUploader.EXPECT().UploadDiagnostics(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("upload-id", nil)

	diagAction := &fleetapi.ActionDiagnostics{}
	handler.collectDiag(context.Background(), diagAction, mockAcker)

	// assert that we logged an ERROR log that includes the error from acker and the action
	assert.Len(t,
		observedLogs.FilterLevelExact(zapcore.ErrorLevel).
			FilterField(zapcore.Field{Key: "error.message", Type: zapcore.ErrorType, Interface: commitError}).
			FilterField(zapcore.Field{Key: "action", Type: zapcore.StringerType, Interface: diagAction}).
			All(),
		1)
	// we could assert the logs for the hooks, but those will be the same as the happy path, so for brevity we won't
}

func TestDiagnosticHandlerContexteExpiredErrorWithLogs(t *testing.T) {
	tempAgentRoot := t.TempDir()
	paths.SetTop(tempAgentRoot)
	err := os.MkdirAll(path.Join(tempAgentRoot, "data"), 0755)
	require.NoError(t, err)

	mockDiagProvider := mocks.NewDiagnosticsProvider(t)
	mockUploader := mocks.NewUploader(t)
	testLogger, observedLogs := logger.NewTesting("diagnostic-handler-test")
	handler := NewDiagnostics(testLogger, mockDiagProvider, defaultRateLimit, mockUploader)

	mockDiagProvider.EXPECT().DiagnosticHooks().Return([]diagnostics.Hook{})

	mockAcker := mocks.NewAcker(t)
	mockAcker.EXPECT().Ack(mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, a fleetapi.Action) error {
		require.IsType(t, new(fleetapi.ActionDiagnostics), a)
		assert.ErrorIs(t, a.(*fleetapi.ActionDiagnostics).Err, context.Canceled)
		return nil
	})

	mockAcker.EXPECT().Commit(mock.Anything).Return(nil)

	diagAction := &fleetapi.ActionDiagnostics{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	handler.collectDiag(ctx, diagAction, mockAcker)

	// assert that we logged an ERROR log that includes the error from running the hooks with an expired context and the action
	assert.Len(t,
		observedLogs.FilterLevelExact(zapcore.ErrorLevel).
			FilterField(zapcore.Field{Key: "error.message", Type: zapcore.ErrorType, Interface: context.Canceled}).
			FilterField(zapcore.Field{Key: "action", Type: zapcore.StringerType, Interface: diagAction}).
			All(),
		1)
	// we could assert the logs for the hooks, but those will be the same as the happy path, so for brevity we won't
}
