// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
)

func TestActionUninstallHandler(t *testing.T) {
	log, _ := loggertest.New("uninstall")

	t.Run("wrong action type", func(t *testing.T) {
		coord := &fakeUninstallCoordinator{}
		h := NewUninstall(log, coord)
		h.tamperProtectionFn = func() bool { return false }

		err := h.Handle(t.Context(), &fleetapi.ActionSettings{}, &fakeAcker{})
		require.Error(t, err)
		coord.AssertNotCalled(t, "Uninstall", mock.Anything, mock.Anything)
	})

	t.Run("happy path spawns uninstaller without acking", func(t *testing.T) {
		action := &fleetapi.ActionUninstall{ActionID: "u1", ActionType: fleetapi.ActionTypeUninstall}

		coord := &fakeUninstallCoordinator{}
		coord.On("Uninstall", mock.Anything, action).Return(nil)

		ack := &fakeAcker{}

		h := NewUninstall(log, coord)
		h.tamperProtectionFn = func() bool { return false }

		require.NoError(t, h.Handle(t.Context(), action, ack))
		coord.AssertCalled(t, "Uninstall", mock.Anything, action)
		// Must NOT ack in the handler; the detached uninstaller acks after the
		// point of no return.
		ack.AssertNotCalled(t, "Ack", mock.Anything, mock.Anything)
	})

	t.Run("expired action acks error and does not uninstall", func(t *testing.T) {
		exp := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		action := &fleetapi.ActionUninstall{
			ActionID:         "u-expired",
			ActionType:       fleetapi.ActionTypeUninstall,
			ActionExpiration: exp,
		}

		coord := &fakeUninstallCoordinator{}

		ack := &fakeAcker{}
		ack.On("Ack", mock.Anything, action).Return(nil)
		ack.On("Commit", mock.Anything).Return(nil)

		h := NewUninstall(log, coord)
		h.tamperProtectionFn = func() bool { return false }

		require.NoError(t, h.Handle(t.Context(), action, ack))
		require.Error(t, action.Err, "expired action should carry an error for the ack")
		coord.AssertNotCalled(t, "Uninstall", mock.Anything, mock.Anything)
		ack.AssertCalled(t, "Ack", mock.Anything, action)
	})

	t.Run("invalid expiration acks error and does not uninstall", func(t *testing.T) {
		action := &fleetapi.ActionUninstall{
			ActionID:         "u-bad-exp",
			ActionType:       fleetapi.ActionTypeUninstall,
			ActionExpiration: "not-a-timestamp",
		}

		coord := &fakeUninstallCoordinator{}

		ack := &fakeAcker{}
		ack.On("Ack", mock.Anything, action).Return(nil)
		ack.On("Commit", mock.Anything).Return(nil)

		h := NewUninstall(log, coord)
		h.tamperProtectionFn = func() bool { return false }

		require.NoError(t, h.Handle(t.Context(), action, ack))
		require.Error(t, action.Err, "malformed expiration should carry an error for the ack")
		coord.AssertNotCalled(t, "Uninstall", mock.Anything, mock.Anything)
		ack.AssertCalled(t, "Ack", mock.Anything, action)
	})

	t.Run("uninstall error acks failure", func(t *testing.T) {
		action := &fleetapi.ActionUninstall{ActionID: "u-fail", ActionType: fleetapi.ActionTypeUninstall}
		uninstallErr := errors.New("not uninstallable")

		coord := &fakeUninstallCoordinator{}
		coord.On("Uninstall", mock.Anything, action).Return(uninstallErr)

		ack := &fakeAcker{}
		ack.On("Ack", mock.Anything, action).Return(nil)
		ack.On("Commit", mock.Anything).Return(nil)

		h := NewUninstall(log, coord)
		h.tamperProtectionFn = func() bool { return false }

		err := h.Handle(t.Context(), action, ack)
		require.ErrorIs(t, err, uninstallErr)
		ack.AssertCalled(t, "Ack", mock.Anything, action)
		require.ErrorIs(t, action.Err, uninstallErr)
	})

	t.Run("tamper protection proxies action to endpoint", func(t *testing.T) {
		action := &fleetapi.ActionUninstall{ActionID: "u-tp", ActionType: fleetapi.ActionTypeUninstall}

		coord := &fakeUninstallCoordinator{}
		// No proxied units configured, so State() is enough and no PerformAction happens.
		coord.On("State").Return(coordinator.State{})
		coord.On("Uninstall", mock.Anything, action).Return(nil)

		h := NewUninstall(log, coord)
		h.tamperProtectionFn = func() bool { return true }

		require.NoError(t, h.Handle(t.Context(), action, &fakeAcker{}))
		coord.AssertCalled(t, "State")
		coord.AssertCalled(t, "Uninstall", mock.Anything, action)
	})
}

type fakeUninstallCoordinator struct {
	mock.Mock
}

func (f *fakeUninstallCoordinator) State() coordinator.State {
	args := f.Called()
	return args.Get(0).(coordinator.State)
}

func (f *fakeUninstallCoordinator) PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
	args := f.Called(ctx, comp, unit, name, params)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (f *fakeUninstallCoordinator) Uninstall(ctx context.Context, action *fleetapi.ActionUninstall) error {
	args := f.Called(ctx, action)
	return args.Error(0)
}
