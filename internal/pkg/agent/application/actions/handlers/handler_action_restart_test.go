// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/protection"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
)

func TestActionRestartHandler(t *testing.T) {
	log, _ := loggertest.New("restart")

	t.Run("wrong action type", func(t *testing.T) {
		coord := &fakeRestartCoordinator{}
		ss := &fakeRestartStateStore{}
		h := NewRestart(log, &info.AgentInfo{}, coord, ss)
		h.tamperProtectionFn = func() bool { return false }

		err := h.Handle(t.Context(), &fleetapi.ActionSettings{}, &fakeAcker{})
		require.Error(t, err)
		coord.AssertNotCalled(t, "Restart", mock.Anything, mock.Anything)
		ss.AssertNotCalled(t, "SetPendingAckAction", mock.Anything)
	})

	t.Run("happy path persists and restarts without acking", func(t *testing.T) {
		action := &fleetapi.ActionRestart{ActionID: "r1", ActionType: fleetapi.ActionTypeRestart}

		coord := &fakeRestartCoordinator{}
		coord.On("Restart", mock.Anything, action).Return(nil)

		ss := &fakeRestartStateStore{}
		ss.On("SetPendingAckAction", action).Return()
		ss.On("Save").Return(nil)

		ack := &fakeAcker{}

		h := NewRestart(log, &info.AgentInfo{}, coord, ss)
		h.tamperProtectionFn = func() bool { return false }

		require.NoError(t, h.Handle(t.Context(), action, ack))
		ss.AssertCalled(t, "SetPendingAckAction", action)
		coord.AssertCalled(t, "Restart", mock.Anything, action)
		// Must NOT ack in the handler; the ack happens after restart on startup.
		ack.AssertNotCalled(t, "Ack", mock.Anything, mock.Anything)
	})

	t.Run("expired action acks error and does not restart", func(t *testing.T) {
		exp := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		action := &fleetapi.ActionRestart{
			ActionID:         "r-expired",
			ActionType:       fleetapi.ActionTypeRestart,
			ActionExpiration: exp,
		}

		coord := &fakeRestartCoordinator{}
		ss := &fakeRestartStateStore{}

		ack := &fakeAcker{}
		ack.On("Ack", mock.Anything, action).Return(nil)
		ack.On("Commit", mock.Anything).Return(nil)

		h := NewRestart(log, &info.AgentInfo{}, coord, ss)
		h.tamperProtectionFn = func() bool { return false }

		require.NoError(t, h.Handle(t.Context(), action, ack))
		require.Error(t, action.Err, "expired action should carry an error for the ack")
		coord.AssertNotCalled(t, "Restart", mock.Anything, mock.Anything)
		ss.AssertNotCalled(t, "SetPendingAckAction", mock.Anything)
		ack.AssertCalled(t, "Ack", mock.Anything, action)
	})

	t.Run("invalid expiration acks error and does not restart", func(t *testing.T) {
		action := &fleetapi.ActionRestart{
			ActionID:         "r-bad-exp",
			ActionType:       fleetapi.ActionTypeRestart,
			ActionExpiration: "not-a-timestamp",
		}

		coord := &fakeRestartCoordinator{}
		ss := &fakeRestartStateStore{}

		ack := &fakeAcker{}
		ack.On("Ack", mock.Anything, action).Return(nil)
		ack.On("Commit", mock.Anything).Return(nil)

		h := NewRestart(log, &info.AgentInfo{}, coord, ss)
		h.tamperProtectionFn = func() bool { return false }

		require.NoError(t, h.Handle(t.Context(), action, ack))
		require.Error(t, action.Err, "malformed expiration should carry an error for the ack")
		coord.AssertNotCalled(t, "Restart", mock.Anything, mock.Anything)
		ss.AssertNotCalled(t, "SetPendingAckAction", mock.Anything)
		ack.AssertCalled(t, "Ack", mock.Anything, action)
	})

	t.Run("restart error clears persisted action and acks failure", func(t *testing.T) {
		action := &fleetapi.ActionRestart{ActionID: "r-fail", ActionType: fleetapi.ActionTypeRestart}
		restartErr := errors.New("not upgradeable")

		coord := &fakeRestartCoordinator{}
		coord.On("Restart", mock.Anything, action).Return(restartErr)

		ss := &fakeRestartStateStore{}
		ss.On("SetPendingAckAction", action).Return()
		ss.On("ClearPendingAckAction").Return()
		ss.On("Save").Return(nil)

		ack := &fakeAcker{}
		ack.On("Ack", mock.Anything, action).Return(nil)
		ack.On("Commit", mock.Anything).Return(nil)

		h := NewRestart(log, &info.AgentInfo{}, coord, ss)
		h.tamperProtectionFn = func() bool { return false }

		err := h.Handle(t.Context(), action, ack)
		require.ErrorIs(t, err, restartErr)
		ss.AssertCalled(t, "ClearPendingAckAction")
		ack.AssertCalled(t, "Ack", mock.Anything, action)
		require.ErrorIs(t, action.Err, restartErr)
	})

	t.Run("required signature missing is rejected and does not restart", func(t *testing.T) {
		action := &fleetapi.ActionRestart{ActionID: "r-unsigned", ActionType: fleetapi.ActionTypeRestart}

		// A signature validation key is configured but the action is not signed.
		coord := &fakeRestartCoordinator{
			protectionConfig: protection.Config{SignatureValidationKey: []byte("validation-key")},
		}
		ss := &fakeRestartStateStore{}
		ack := &fakeAcker{}

		h := NewRestart(log, &info.AgentInfo{}, coord, ss)
		h.tamperProtectionFn = func() bool { return false }

		err := h.Handle(t.Context(), action, ack)
		require.ErrorIs(t, err, protection.ErrNotSigned)
		coord.AssertNotCalled(t, "Restart", mock.Anything, mock.Anything)
		ss.AssertNotCalled(t, "SetPendingAckAction", mock.Anything)
		ack.AssertNotCalled(t, "Ack", mock.Anything, mock.Anything)
	})

	t.Run("signed expired action with tampered future outer expiration is rejected", func(t *testing.T) {
		past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

		// The signed envelope carries an expired expiration, but the outer
		// expiration is tampered to a future time. The handler must trust the
		// verified signed expiration and reject the action as expired. The agents
		// list must contain the agent ID, which is empty for &info.AgentInfo{}.
		envelope, err := json.Marshal(map[string]any{
			"action_id":  "r-signed-exp",
			"type":       fleetapi.ActionTypeRestart,
			"agents":     []string{""},
			"data":       map[string]any{},
			"expiration": past,
		})
		require.NoError(t, err)

		action := &fleetapi.ActionRestart{
			ActionID:         "r-signed-exp",
			ActionType:       fleetapi.ActionTypeRestart,
			ActionExpiration: future, // tampered outer value
			Signature: &fleetapi.Signed{
				Data:      base64.StdEncoding.EncodeToString(envelope),
				Signature: base64.StdEncoding.EncodeToString([]byte("signature")),
			},
		}

		coord := &fakeRestartCoordinator{}
		ss := &fakeRestartStateStore{}

		ack := &fakeAcker{}
		ack.On("Ack", mock.Anything, action).Return(nil)
		ack.On("Commit", mock.Anything).Return(nil)

		// No validation key configured: the signed envelope is still parsed and
		// its expiration used, but the signature bytes are not cryptographically
		// verified (which requires a key).
		h := NewRestart(log, &info.AgentInfo{}, coord, ss)
		h.tamperProtectionFn = func() bool { return false }

		require.NoError(t, h.Handle(t.Context(), action, ack))
		require.Error(t, action.Err, "expired signed action should carry an error for the ack")
		coord.AssertNotCalled(t, "Restart", mock.Anything, mock.Anything)
		ss.AssertNotCalled(t, "SetPendingAckAction", mock.Anything)
		ack.AssertCalled(t, "Ack", mock.Anything, action)
	})

	t.Run("tamper protection proxies action to endpoint", func(t *testing.T) {
		action := &fleetapi.ActionRestart{ActionID: "r-tp", ActionType: fleetapi.ActionTypeRestart}

		coord := &fakeRestartCoordinator{}
		// No proxied units configured, so State() is enough and no PerformAction happens.
		coord.On("State").Return(coordinator.State{})
		coord.On("Restart", mock.Anything, action).Return(nil)

		ss := &fakeRestartStateStore{}
		ss.On("SetPendingAckAction", action).Return()
		ss.On("Save").Return(nil)

		h := NewRestart(log, &info.AgentInfo{}, coord, ss)
		h.tamperProtectionFn = func() bool { return true }

		require.NoError(t, h.Handle(t.Context(), action, &fakeAcker{}))
		coord.AssertCalled(t, "State")
		coord.AssertCalled(t, "Restart", mock.Anything, action)
	})
}

type fakeRestartCoordinator struct {
	mock.Mock
	protectionConfig protection.Config
}

func (f *fakeRestartCoordinator) Protection() protection.Config {
	return f.protectionConfig
}

func (f *fakeRestartCoordinator) State() coordinator.State {
	args := f.Called()
	return args.Get(0).(coordinator.State)
}

func (f *fakeRestartCoordinator) PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
	args := f.Called(ctx, comp, unit, name, params)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (f *fakeRestartCoordinator) Restart(ctx context.Context, action *fleetapi.ActionRestart) error {
	args := f.Called(ctx, action)
	return args.Error(0)
}

type fakeRestartStateStore struct {
	mock.Mock
}

func (f *fakeRestartStateStore) SetPendingAckAction(a fleetapi.Action) {
	f.Called(a)
}

func (f *fakeRestartStateStore) ClearPendingAckAction() {
	f.Called()
}

func (f *fakeRestartStateStore) Save() error {
	args := f.Called()
	return args.Error(0)
}
