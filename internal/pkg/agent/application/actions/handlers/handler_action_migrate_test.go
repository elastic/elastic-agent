// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	mockinfo "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/agent/application/info"
)

func TestActionMigratelHandler(t *testing.T) {
	log, _ := loggertest.New("")
	mockAgentInfo := mockinfo.NewAgent(t)
	t.Run("wrong action type", func(t *testing.T) {
		action := &fleetapi.ActionSettings{}
		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("Migrate", mock.Anything, mock.Anything).Return(nil)
		coord.On("ReExec", mock.Anything, mock.Anything)

		h := NewMigrate(log, mockAgentInfo, coord)
		require.NotNil(t, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 0)
		coord.AssertNumberOfCalls(t, "ReExec", 0)
	})

	t.Run("tamper protected agent", func(t *testing.T) {
		action := &fleetapi.ActionMigrate{
			ActionType: "MIGRATE",
		}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("Migrate", mock.Anything, mock.Anything).Return(nil)
		coord.On("ReExec", mock.Anything, mock.Anything)
		coord.On("HasEndpoint").Return(true)

		h := NewMigrate(log, mockAgentInfo, coord)
		h.tamperProtectionFn = func() bool { return true }

		require.NotNil(t, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 0)
		ack.AssertCalled(t, "Ack", t.Context(), action)
		ack.AssertCalled(t, "Commit", t.Context())
		coord.AssertNumberOfCalls(t, "ReExec", 0)
	})

	t.Run("action propagated to coordinator", func(t *testing.T) {
		action := &fleetapi.ActionMigrate{}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("Migrate", mock.Anything, mock.Anything).Return(nil)
		coord.On("ReExec", mock.Anything, mock.Anything)

		h := NewMigrate(log, mockAgentInfo, coord)
		h.tamperProtectionFn = func() bool { return false }

		require.Nil(t, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 1)

		// ack delegated to migrate coordinator
		ack.AssertNumberOfCalls(t, "Ack", 0)
		ack.AssertNumberOfCalls(t, "Commit", 0)
		coord.AssertCalled(t, "ReExec", mock.Anything, mock.Anything)
	})

	t.Run("fleet server", func(t *testing.T) {
		action := &fleetapi.ActionMigrate{}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("Migrate", mock.Anything, mock.Anything).Return(coordinator.ErrFleetServer)
		coord.On("ReExec", mock.Anything, mock.Anything)

		h := NewMigrate(log, mockAgentInfo, coord)
		h.tamperProtectionFn = func() bool { return false }

		require.Error(t, coordinator.ErrFleetServer, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 1)

		// ack not delegated to migrate coordinator, failure is reported
		ack.AssertNumberOfCalls(t, "Ack", 1)
		ack.AssertNumberOfCalls(t, "Commit", 1)
		coord.AssertNotCalled(t, "ReExec", mock.Anything, mock.Anything)
	})
}

type fakeMigrateCoordinator struct {
	mock.Mock
}

func (f *fakeMigrateCoordinator) Migrate(ctx context.Context, a *fleetapi.ActionMigrate, _ func(done <-chan struct{}) backoff.Backoff) error {
	args := f.Called(ctx, a)
	return args.Error(0)
}

func (f *fakeMigrateCoordinator) ReExec(callback reexec.ShutdownCallbackFn, argOverrides ...string) {
	f.Called(callback, argOverrides)
}

func (f *fakeMigrateCoordinator) HasEndpoint() bool {
	args := f.Called()
	return args.Bool(0)
}
