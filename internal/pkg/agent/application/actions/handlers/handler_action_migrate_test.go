// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/protection"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestActionMigratelHandler(t *testing.T) {
	log, _ := loggertest.New("")
	t.Run("wrong action type", func(t *testing.T) {

		mockAgentInfo := info.NewMockAgent(t)

		action := &fleetapi.ActionSettings{}
		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("Migrate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		coord.On("ReExec", mock.Anything, mock.Anything)
		coord.On("Protection").Return(protection.Config{SignatureValidationKey: nil})

		h := NewMigrate(log, mockAgentInfo, coord)
		require.NotNil(t, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 0)
		coord.AssertNumberOfCalls(t, "ReExec", 0)
	})

	t.Run("tamper protected agent", func(t *testing.T) {
		tamperCases := []struct {
			name              string
			featureEnabled    bool
			protectionEnabled bool
			expectedRun       bool
		}{
			{"F1E1", true, true, false},
			{"F0E1", false, true, true},
			{"F0E0", false, false, true},
			{"F1E0", false, false, true},
		}

		for _, tc := range tamperCases {
			t.Run("tamper protected agent - "+tc.name, func(t *testing.T) {
				mockAgentInfo := info.NewMockAgent(t)
				if tc.expectedRun {
					mockAgentInfo.On("AgentID").Return("agent-id")
				}

				action := &fleetapi.ActionMigrate{
					ActionType: "MIGRATE",
				}

				ack := &fakeAcker{}
				ack.On("Ack", t.Context(), action).Return(nil)
				ack.On("Commit", t.Context()).Return(nil)

				coord := &fakeMigrateCoordinator{}
				coord.On("State").Return(coordinator.State{})
				coord.On("Migrate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				coord.On("ReExec", mock.Anything, mock.Anything)
				coord.On("Protection").Return(protection.Config{SignatureValidationKey: nil, Enabled: tc.protectionEnabled})

				h := NewMigrate(log, mockAgentInfo, coord)
				h.tamperProtectionFn = func() bool { return tc.featureEnabled }

				if !tc.expectedRun {
					require.NotNil(t, h.Handle(t.Context(), action, ack))
					coord.AssertNumberOfCalls(t, "Migrate", 0)
					ack.AssertCalled(t, "Ack", t.Context(), action)
					ack.AssertCalled(t, "Commit", t.Context())
					coord.AssertNumberOfCalls(t, "ReExec", 0)
				} else {

					require.Nil(t, h.Handle(t.Context(), action, ack))
					coord.AssertNumberOfCalls(t, "Migrate", 1)

					// ack delegated to migrate coordinator
					ack.AssertNumberOfCalls(t, "Ack", 0)
					ack.AssertNumberOfCalls(t, "Commit", 0)
					coord.AssertCalled(t, "ReExec", mock.Anything, mock.Anything)
				}
			})
		}
	})

	t.Run("action propagated to coordinator", func(t *testing.T) {
		mockAgentInfo := info.NewMockAgent(t)
		mockAgentInfo.On("AgentID").Return("agent-id")
		action := &fleetapi.ActionMigrate{}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("State").Return(coordinator.State{})
		coord.On("Migrate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		coord.On("ReExec", mock.Anything, mock.Anything)
		coord.On("Protection").Return(protection.Config{SignatureValidationKey: nil})

		h := NewMigrate(log, mockAgentInfo, coord)
		h.tamperProtectionFn = func() bool { return false }

		require.Nil(t, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 1)

		// ack delegated to migrate coordinator
		ack.AssertNumberOfCalls(t, "Ack", 0)
		ack.AssertNumberOfCalls(t, "Commit", 0)
		coord.AssertCalled(t, "ReExec", mock.Anything, mock.Anything)
	})

	t.Run("signature present", func(t *testing.T) {
		mockAgentInfo := info.NewMockAgent(t)
		mockAgentInfo.On("AgentID").Return("agent-id")

		private, signatureValidationKey, err := genKeys()
		require.NoError(t, err)

		action := &fleetapi.ActionMigrate{
			ActionID:   "123",
			ActionType: "MIGRATE",
			Data: fleetapi.ActionMigrateData{
				EnrollmentToken: "et-123",
			},
		}

		actionBytes := []byte("{\"action_id\":\"123\",\"agents\":[\"agent-id\"],\"type\":\"MIGRATE\",\"data\":{\"target_uri\":\"\",\"enrollment_token\":\"et-123\",\"settings\":null}}")

		signature, err := sign(actionBytes, private)
		require.NoError(t, err)

		base64Data := base64.StdEncoding.EncodeToString(actionBytes)
		base64Signature := base64.StdEncoding.EncodeToString(signature)

		action.Signature = &fleetapi.Signed{
			Data:      base64Data,
			Signature: base64Signature,
		}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("State").Return(coordinator.State{})
		coord.On("Migrate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		coord.On("ReExec", mock.Anything, mock.Anything)
		coord.On("Protection").Return(protection.Config{SignatureValidationKey: signatureValidationKey})

		h := NewMigrate(log, mockAgentInfo, coord)
		h.tamperProtectionFn = func() bool { return false }

		require.Nil(t, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 1)

		// ack delegated to migrate coordinator
		ack.AssertNumberOfCalls(t, "Ack", 0)
		ack.AssertNumberOfCalls(t, "Commit", 0)
		coord.AssertCalled(t, "ReExec", mock.Anything, mock.Anything)
	})

	t.Run("signature present, action not signed", func(t *testing.T) {
		mockAgentInfo := info.NewMockAgent(t)
		mockAgentInfo.On("AgentID").Return("agent-id")

		_, signatureValidationKey, err := genKeys()
		require.NoError(t, err)

		action := &fleetapi.ActionMigrate{
			ActionID:   "123",
			ActionType: "MIGRATE",
			Data: fleetapi.ActionMigrateData{
				EnrollmentToken: "et-123",
			},
		}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("Migrate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		coord.On("ReExec", mock.Anything, mock.Anything)
		coord.On("Protection").Return(protection.Config{SignatureValidationKey: signatureValidationKey})

		h := NewMigrate(log, mockAgentInfo, coord)
		h.tamperProtectionFn = func() bool { return false }

		require.ErrorIs(t, h.Handle(t.Context(), action, ack), protection.ErrNotSigned)
		coord.AssertNumberOfCalls(t, "Migrate", 0)

		// ack delegated to migrate coordinator
		ack.AssertNumberOfCalls(t, "Ack", 0)
		ack.AssertNumberOfCalls(t, "Commit", 0)
		coord.AssertNumberOfCalls(t, "ReExec", 0)
	})

	t.Run("signature not present", func(t *testing.T) {
		mockAgentInfo := info.NewMockAgent(t)
		mockAgentInfo.On("AgentID").Return("agent-id")

		private, _, err := genKeys()
		require.NoError(t, err)

		action := &fleetapi.ActionMigrate{
			ActionID:   "123",
			ActionType: "MIGRATE",
			Data: fleetapi.ActionMigrateData{
				EnrollmentToken: "et-123",
			},
		}

		actionBytes := []byte("{\"action_id\":\"123\",\"agents\":[\"agent-id\"],\"type\":\"MIGRATE\",\"data\":{\"target_uri\":\"\",\"enrollment_token\":\"et-123\",\"settings\":null}}")

		signature, err := sign(actionBytes, private)
		require.NoError(t, err)

		base64Data := base64.StdEncoding.EncodeToString(actionBytes)
		base64Signature := base64.StdEncoding.EncodeToString(signature)

		action.Signature = &fleetapi.Signed{
			Data:      base64Data,
			Signature: base64Signature,
		}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("State").Return(coordinator.State{})
		coord.On("Migrate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		coord.On("ReExec", mock.Anything, mock.Anything)
		coord.On("Protection").Return(protection.Config{SignatureValidationKey: nil})

		h := NewMigrate(log, mockAgentInfo, coord)
		h.tamperProtectionFn = func() bool { return false }

		require.Nil(t, h.Handle(t.Context(), action, ack))
		coord.AssertNumberOfCalls(t, "Migrate", 1)

		// ack delegated to migrate coordinator
		ack.AssertNumberOfCalls(t, "Ack", 0)
		ack.AssertNumberOfCalls(t, "Commit", 0)
		coord.AssertCalled(t, "ReExec", mock.Anything, mock.Anything)
	})

	t.Run("malformed signature", func(t *testing.T) {
		mockAgentInfo := info.NewMockAgent(t)
		mockAgentInfo.On("AgentID").Return("agent-id")

		_, signatureValidationKey, err := genKeys()
		require.NoError(t, err)

		private, _, err := genKeys()
		require.NoError(t, err)

		action := &fleetapi.ActionMigrate{
			ActionID:   "123",
			ActionType: "MIGRATE",
			Data: fleetapi.ActionMigrateData{
				EnrollmentToken: "et-123",
			},
		}

		actionBytes := []byte("{\"action_id\":\"123\",\"agents\":[\"agent-id\"],\"type\":\"MIGRATE\",\"data\":{\"target_uri\":\"\",\"enrollment_token\":\"et-123\",\"settings\":null}}")

		signature, err := sign(actionBytes, private)
		require.NoError(t, err)

		base64Data := base64.StdEncoding.EncodeToString(actionBytes)
		base64Signature := base64.StdEncoding.EncodeToString(signature)

		action.Signature = &fleetapi.Signed{
			Data:      base64Data,
			Signature: base64Signature,
		}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("Migrate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		coord.On("ReExec", mock.Anything, mock.Anything)
		coord.On("Protection").Return(protection.Config{SignatureValidationKey: signatureValidationKey})

		h := NewMigrate(log, mockAgentInfo, coord)
		h.tamperProtectionFn = func() bool { return false }

		err = h.Handle(t.Context(), action, ack)
		require.ErrorIs(t, err, protection.ErrInvalidSignature)
		coord.AssertNumberOfCalls(t, "Migrate", 0)
	})

	t.Run("fleet server", func(t *testing.T) {
		mockAgentInfo := info.NewMockAgent(t)
		mockAgentInfo.On("AgentID").Return("agent-id")
		action := &fleetapi.ActionMigrate{}

		ack := &fakeAcker{}
		ack.On("Ack", t.Context(), action).Return(nil)
		ack.On("Commit", t.Context()).Return(nil)

		coord := &fakeMigrateCoordinator{}
		coord.On("State").Return(coordinator.State{})
		coord.On("Migrate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(coordinator.ErrFleetServer)
		coord.On("ReExec", mock.Anything, mock.Anything)
		coord.On("Protection").Return(protection.Config{SignatureValidationKey: nil})

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

func (f *fakeMigrateCoordinator) Migrate(ctx context.Context, a *fleetapi.ActionMigrate, b func(done <-chan struct{}) backoff.Backoff, n func(context.Context, *fleetapi.ActionMigrate) error) error {
	args := f.Called(ctx, a, b, n)
	return args.Error(0)
}

func (f *fakeMigrateCoordinator) State() coordinator.State {
	args := f.Called()
	return args.Get(0).(coordinator.State)
}

func (f *fakeMigrateCoordinator) PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
	args := f.Called(ctx, comp, unit, name, params)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (f *fakeMigrateCoordinator) ReExec(callback reexec.ShutdownCallbackFn, argOverrides ...string) {
	f.Called(callback, argOverrides)
}

func (f *fakeMigrateCoordinator) HasEndpoint() bool {
	args := f.Called()
	return args.Bool(0)
}

func (f *fakeMigrateCoordinator) Protection() protection.Config {
	args := f.Called()
	return args.Get(0).(protection.Config)
}

func genKeys() (pk *ecdsa.PrivateKey, pubK []byte, err error) {
	pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	pubK, err = x509.MarshalPKIXPublicKey(&pk.PublicKey)
	return pk, pubK, err
}

func sign(data []byte, pk *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, pk, hash[:])
}
