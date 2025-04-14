// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	mockinfo "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/agent/application/info"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

		h := NewMigrate(log, mockAgentInfo, coord)
		require.NotNil(t, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 0)
	})

	t.Run("tamper protected agent", func(t *testing.T) {
		action := &fleetapi.ActionMigrate{}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("Migrate", mock.Anything, mock.Anything).Return(nil)

		h := NewMigrate(log, mockAgentInfo, coord)
		h.tamperProtectionFn = func() bool { return true }

		require.NotNil(t, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 0)
		ack.AssertCalled(t, "Ack", t.Context(), action)
		ack.AssertCalled(t, "Commit", t.Context())
	})

	t.Run("action propagated to coordinator", func(t *testing.T) {
		action := &fleetapi.ActionMigrate{}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("Migrate", mock.Anything, mock.Anything).Return(nil)

		h := NewMigrate(log, mockAgentInfo, coord)
		h.tamperProtectionFn = func() bool { return false }

		require.Nil(t, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 1)

		// ack delegated to migrate coordinator
		ack.AssertNumberOfCalls(t, "Ack", 0)
		ack.AssertNumberOfCalls(t, "Migrate", 0)
	})
}

type fakeMigrateCoordinator struct {
	mock.Mock
}

func (f *fakeMigrateCoordinator) Migrate(ctx context.Context, a *fleetapi.ActionMigrate) error {
	args := f.Called(ctx, a)
	return args.Error(0)
}
