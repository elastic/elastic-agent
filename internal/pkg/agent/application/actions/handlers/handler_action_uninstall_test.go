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

func TestActionUninstallHandler(t *testing.T) {
	log, _ := loggertest.New("uninstall")

	t.Run("wrong action type", func(t *testing.T) {
		coord := &fakeUninstallCoordinator{}
		h := NewUninstall(log, &info.AgentInfo{}, coord)

		err := h.Handle(t.Context(), &fleetapi.ActionSettings{}, &fakeAcker{})
		require.Error(t, err)
		coord.AssertNotCalled(t, "Uninstall", mock.Anything, mock.Anything)
	})

	t.Run("happy path spawns uninstaller without acking", func(t *testing.T) {
		action := &fleetapi.ActionUninstall{ActionID: "u1", ActionType: fleetapi.ActionTypeUninstall}

		coord := &fakeUninstallCoordinator{}
		coord.On("Uninstall", mock.Anything, action).Return(nil)

		ack := &fakeAcker{}

		h := NewUninstall(log, &info.AgentInfo{}, coord)

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

		h := NewUninstall(log, &info.AgentInfo{}, coord)

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

		h := NewUninstall(log, &info.AgentInfo{}, coord)

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

		h := NewUninstall(log, &info.AgentInfo{}, coord)

		err := h.Handle(t.Context(), action, ack)
		require.ErrorIs(t, err, uninstallErr)
		ack.AssertCalled(t, "Ack", mock.Anything, action)
		require.ErrorIs(t, action.Err, uninstallErr)
	})

	t.Run("action pre-rejected by the dispatcher acks failure and does not uninstall", func(t *testing.T) {
		action := &fleetapi.ActionUninstall{
			ActionID:   "u-prerejected",
			ActionType: fleetapi.ActionTypeUninstall,
			Err:        errors.New("grace period ends after expiration"),
		}

		coord := &fakeUninstallCoordinator{}
		ack := &fakeAcker{}
		ack.On("Ack", mock.Anything, action).Return(nil)
		ack.On("Commit", mock.Anything).Return(nil)

		h := NewUninstall(log, &info.AgentInfo{}, coord)

		require.NoError(t, h.Handle(t.Context(), action, ack))
		coord.AssertNotCalled(t, "Uninstall", mock.Anything, mock.Anything)
		ack.AssertCalled(t, "Ack", mock.Anything, action)
	})

	t.Run("required signature missing is rejected and does not uninstall", func(t *testing.T) {
		action := &fleetapi.ActionUninstall{ActionID: "u-unsigned", ActionType: fleetapi.ActionTypeUninstall}

		// A signature validation key is configured but the action is not signed.
		coord := &fakeUninstallCoordinator{
			protectionConfig: protection.Config{SignatureValidationKey: []byte("validation-key")},
		}

		ack := &fakeAcker{}
		h := NewUninstall(log, &info.AgentInfo{}, coord)

		err := h.Handle(t.Context(), action, ack)
		require.ErrorIs(t, err, protection.ErrNotSigned)
		coord.AssertNotCalled(t, "Uninstall", mock.Anything, mock.Anything)
		ack.AssertNotCalled(t, "Ack", mock.Anything, mock.Anything)
	})

	// The expiry check must trust the signed expiration, not the mutable outer
	// one. (&info.AgentInfo{}).AgentID() is "", so the signed payload lists "" as
	// its agent.
	t.Run("expired signed expiration rejects even when the outer expiration is in the future", func(t *testing.T) {
		priv, pubDER := genSignKey(t)
		action := &fleetapi.ActionUninstall{
			ActionID:         "u-sig-expired",
			ActionType:       fleetapi.ActionTypeUninstall,
			ActionExpiration: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), // outer: not expired
		}
		action.Signature = signUninstallAction(t, action.ActionID, "",
			time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), priv) // signed: expired

		coord := &fakeUninstallCoordinator{protectionConfig: protection.Config{SignatureValidationKey: pubDER}}
		ack := &fakeAcker{}
		ack.On("Ack", mock.Anything, action).Return(nil)
		ack.On("Commit", mock.Anything).Return(nil)

		h := NewUninstall(log, &info.AgentInfo{}, coord)
		require.NoError(t, h.Handle(t.Context(), action, ack))
		require.Error(t, action.Err, "the signed (expired) expiration must cause rejection despite a future outer expiration")
		coord.AssertNotCalled(t, "Uninstall", mock.Anything, mock.Anything)
		ack.AssertCalled(t, "Ack", mock.Anything, action)
	})

	t.Run("valid signed expiration proceeds even when the outer expiration is in the past", func(t *testing.T) {
		priv, pubDER := genSignKey(t)
		action := &fleetapi.ActionUninstall{
			ActionID:         "u-sig-valid",
			ActionType:       fleetapi.ActionTypeUninstall,
			ActionExpiration: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), // outer: expired (untrusted)
		}
		action.Signature = signUninstallAction(t, action.ActionID, "",
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339), priv) // signed: not expired

		coord := &fakeUninstallCoordinator{protectionConfig: protection.Config{SignatureValidationKey: pubDER}}
		coord.On("Uninstall", mock.Anything, action).Return(nil)
		ack := &fakeAcker{}

		h := NewUninstall(log, &info.AgentInfo{}, coord)
		require.NoError(t, h.Handle(t.Context(), action, ack))
		coord.AssertCalled(t, "Uninstall", mock.Anything, action)
		ack.AssertNotCalled(t, "Ack", mock.Anything, mock.Anything)
	})
}

// genSignKey returns an ECDSA private key and the DER-encoded PKIX public key to
// use as protection.Config.SignatureValidationKey.
func genSignKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return priv, pubDER
}

// signUninstallAction builds a signed envelope for an UNINSTALL action whose
// signed payload carries the given expiration, signed with priv. This mirrors
// how Kibana signs actions so the agent's in-agent verification trusts the
// signed fields over the mutable outer JSON.
func signUninstallAction(t *testing.T, actionID, agentID, signedExpiration string, priv *ecdsa.PrivateKey) *fleetapi.Signed {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"action_id":  actionID,
		"type":       fleetapi.ActionTypeUninstall,
		"agents":     []string{agentID},
		"expiration": signedExpiration,
	})
	require.NoError(t, err)
	hash := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	require.NoError(t, err)
	return &fleetapi.Signed{
		Data:      base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

type fakeUninstallCoordinator struct {
	mock.Mock
	protectionConfig protection.Config
}

func (f *fakeUninstallCoordinator) Protection() protection.Config {
	return f.protectionConfig
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
