// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/component/runtime"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	noopacker "github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type mockUpgradeManager struct {
	UpgradeFn func(
		ctx context.Context,
		version string,
		sourceURI string,
		action *fleetapi.ActionUpgrade,
		details *details.Details,
		skipVerifyOverride bool,
		skipDefaultPgp bool,
		pgpBytes ...string) (reexec.ShutdownCallbackFn, error)
}

func (u *mockUpgradeManager) Upgradeable() bool {
	return true
}

func (u *mockUpgradeManager) Reload(rawConfig *config.Config) error {
	return nil
}

func (u *mockUpgradeManager) Upgrade(ctx context.Context, version string, rollback bool, sourceURI string, action *fleetapi.ActionUpgrade, details *details.Details, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (reexec.ShutdownCallbackFn, error) {

	return u.UpgradeFn(
		ctx,
		version,
		sourceURI,
		action,
		details,
		skipVerifyOverride,
		skipDefaultPgp,
		pgpBytes...)
}

func (u *mockUpgradeManager) Ack(_ context.Context, _ acker.Acker) error {
	return nil
}

func (u *mockUpgradeManager) AckAction(_ context.Context, _ acker.Acker, _ fleetapi.Action) error {
	return nil
}

func (u *mockUpgradeManager) MarkerWatcher() upgrade.MarkerWatcher {
	return nil
}

func TestUpgradeHandler(t *testing.T) {
	// Create a cancellable context that will shut down the coordinator after
	// the test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log, _ := logger.New("", false)

	agentInfo := &info.AgentInfo{}
	upgradeCalledChan := make(chan struct{})

	// Create and start the coordinator
	c := coordinator.New(
		log,
		configuration.DefaultConfiguration(),
		logger.DefaultLogLevel,
		agentInfo,
		component.RuntimeSpecs{},
		nil,
		&mockUpgradeManager{
			UpgradeFn: func(
				ctx context.Context,
				version string,
				sourceURI string,
				action *fleetapi.ActionUpgrade,
				details *details.Details,
				skipVerifyOverride bool,
				skipDefaultPgp bool,
				pgpBytes ...string) (reexec.ShutdownCallbackFn, error) {

				upgradeCalledChan <- struct{}{}
				return nil, nil
			},
		},
		nil, nil, nil, nil, nil, false, nil, nil, nil)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a := fleetapi.ActionUpgrade{Data: fleetapi.ActionUpgradeData{
		Version: "8.3.0", SourceURI: "http://localhost"}}
	ack := noopacker.New()
	err := u.Handle(ctx, &a, ack)
	require.NoError(t, err)

	// Make sure this test does not dead lock or wait for too long
	select {
	case <-time.Tick(1 * time.Second):
		t.Fatal("mockUpgradeManager.Upgrade was not called")
	case <-upgradeCalledChan:
	}
}

func TestUpgradeHandlerSameVersion(t *testing.T) {
	// Create a cancellable context that will shut down the coordinator after
	// the test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log, _ := logger.New("", false)

	agentInfo := &info.AgentInfo{}
	upgradeCalledChan := make(chan struct{})

	// Create and start the Coordinator
	upgradeCalled := atomic.Bool{}
	c := coordinator.New(
		log,
		configuration.DefaultConfiguration(),
		logger.DefaultLogLevel,
		agentInfo,
		component.RuntimeSpecs{},
		nil,
		&mockUpgradeManager{
			UpgradeFn: func(
				ctx context.Context,
				version string,
				sourceURI string,
				action *fleetapi.ActionUpgrade,
				details *details.Details,
				skipVerifyOverride bool,
				skipDefaultPgp bool,
				pgpBytes ...string) (reexec.ShutdownCallbackFn, error) {

				if upgradeCalled.CompareAndSwap(false, true) {
					upgradeCalledChan <- struct{}{}
					return nil, nil
				}
				err := errors.New("mockUpgradeManager.Upgrade called more than once")
				t.Error(err.Error())
				return nil, err
			},
		},
		nil, nil, nil, nil, nil, false, nil, nil, nil)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a := fleetapi.ActionUpgrade{Data: fleetapi.ActionUpgradeData{
		Version: "8.3.0", SourceURI: "http://localhost"}}
	ack := noopacker.New()
	err1 := u.Handle(ctx, &a, ack)
	err2 := u.Handle(ctx, &a, ack)
	require.NoError(t, err1)
	require.NoError(t, err2)

	// Make sure this test does not dead lock or wait for too long
	select {
	case <-time.Tick(1 * time.Second):
		t.Fatal("mockUpgradeManager.Upgrade was not called")
	case <-upgradeCalledChan:
	}
}

func TestDuplicateActionsHandled(t *testing.T) {
	// Create a cancellable context that will shut down the coordinator after
	// the test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log, _ := logger.New("", false)
	upgradeCalledChan := make(chan string)

	agentInfo := &info.AgentInfo{}
	acker := &fakeAcker{}

	// Create and start the Coordinator
	c := coordinator.New(
		log,
		configuration.DefaultConfiguration(),
		logger.DefaultLogLevel,
		agentInfo,
		component.RuntimeSpecs{},
		nil,
		&mockUpgradeManager{
			UpgradeFn: func(
				ctx context.Context,
				version string,
				sourceURI string,
				action *fleetapi.ActionUpgrade,
				details *details.Details,
				skipVerifyOverride bool,
				skipDefaultPgp bool,
				pgpBytes ...string) (reexec.ShutdownCallbackFn, error) {

				defer func() {
					upgradeCalledChan <- action.ActionID
				}()

				return nil, nil
			},
		},
		nil, nil, nil, nil, nil, false, nil, acker, nil)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a1 := fleetapi.ActionUpgrade{
		ActionID: "action-8.5-1",
		Data: fleetapi.ActionUpgradeData{
			Version: "8.5.0", SourceURI: "http://localhost",
		},
	}
	a2 := fleetapi.ActionUpgrade{
		ActionID: "action-8.5-2",
		Data: fleetapi.ActionUpgradeData{
			Version: "8.5.0", SourceURI: "http://localhost",
		},
	}

	checkMsg := func(c <-chan string, expected, errMsg string) error {
		t.Helper()
		// Make sure this test does not dead lock or wait for too long
		// For some reason < 1s sometimes makes the test fail.
		select {
		case <-time.Tick(1500 * time.Millisecond):
			return errors.New("timed out waiting for Upgrade to return")
		case msg := <-c:
			require.Equal(t, expected, msg, errMsg)
		}

		return nil
	}

	acker.On("Ack", mock.Anything, mock.Anything).Return(nil)
	acker.On("Commit", mock.Anything).Return(nil)

	t.Log("First upgrade action should be processed")
	require.NoError(t, u.Handle(ctx, &a1, acker))
	require.Nil(t, checkMsg(upgradeCalledChan, a1.ActionID, "action was not processed"))
	c.ClearOverrideState() // it's upgrading, normally we would restart

	t.Log("Action with different ID but same version should not be propagated to upgrader but acked")
	require.NoError(t, u.Handle(ctx, &a2, acker))
	require.NotNil(t, checkMsg(upgradeCalledChan, a2.ActionID, "action was not processed"))
	acker.AssertCalled(t, "Ack", ctx, &a2)
	acker.AssertCalled(t, "Commit", ctx)

	c.ClearOverrideState() // it's upgrading, normally we would restart

	t.Log("Resending action with same ID should be skipped")
	require.NoError(t, u.Handle(ctx, &a1, acker))
	require.NotNil(t, checkMsg(upgradeCalledChan, a1.ActionID, "action was not processed"))
	acker.AssertNotCalled(t, "Ack", ctx, &a1)
}

func TestUpgradeHandlerNewVersion(t *testing.T) {
	// Create a cancellable context that will shut down the coordinator after
	// the test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log, _ := logger.New("", false)
	upgradeCalledChan := make(chan string)

	agentInfo := &info.AgentInfo{}

	// Create and start the Coordinator
	c := coordinator.New(
		log,
		configuration.DefaultConfiguration(),
		logger.DefaultLogLevel,
		agentInfo,
		component.RuntimeSpecs{},
		nil,
		&mockUpgradeManager{
			UpgradeFn: func(
				ctx context.Context,
				version string,
				sourceURI string,
				action *fleetapi.ActionUpgrade,
				details *details.Details,
				skipVerifyOverride bool,
				skipDefaultPgp bool,
				pgpBytes ...string) (reexec.ShutdownCallbackFn, error) {

				defer func() {
					upgradeCalledChan <- version
				}()
				if version == "8.2.0" {
					return nil, errors.New("upgrade to 8.2.0 will always fail")
				}

				return nil, nil
			},
		},
		nil, nil, nil, nil, nil, false, nil, nil, nil)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a1 := fleetapi.ActionUpgrade{
		ActionID: "action-8.2",
		Data: fleetapi.ActionUpgradeData{
			Version: "8.2.0", SourceURI: "http://localhost",
		},
	}
	a2 := fleetapi.ActionUpgrade{
		ActionID: "action-8.5",
		Data: fleetapi.ActionUpgradeData{
			Version: "8.5.0", SourceURI: "http://localhost",
		},
	}
	ack := noopacker.New()

	checkMsg := func(c <-chan string, expected, errMsg string) {
		t.Helper()
		// Make sure this test does not dead lock or wait for too long
		// For some reason < 1s sometimes makes the test fail.
		select {
		case <-time.Tick(1300 * time.Millisecond):
			t.Fatal("timed out waiting for Upgrade to return")
		case msg := <-c:
			require.Equal(t, expected, msg, errMsg)
		}
	}

	// Send both upgrade actions, a1 will error before a2 succeeds
	err1 := u.Handle(ctx, &a1, ack)
	require.NoError(t, err1)
	checkMsg(upgradeCalledChan, "8.2.0", "first call must be with version 8.2.0")

	err2 := u.Handle(ctx, &a2, ack)
	require.NoError(t, err2)
	checkMsg(upgradeCalledChan, "8.5.0", "second call to Upgrade must be with version 8.5.0")
}

func TestEndpointPreUpgradeCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	for _, tc := range []struct {
		name                  string
		upgradeAction         *fleetapi.ActionUpgrade
		shouldProxyToEndpoint bool
		coordUpgradeErr       error
	}{
		{
			name: "error from coordinator upgrade with notify endpoint",
			upgradeAction: &fleetapi.ActionUpgrade{
				ActionType: fleetapi.ActionTypeUpgrade,
				Data: fleetapi.ActionUpgradeData{
					Version:   "255.0.0",
					SourceURI: "http://localhost",
				},
			},
			shouldProxyToEndpoint: true,
			coordUpgradeErr:       errors.New("test error"),
		},
		{
			name: "no error from coordinator upgrade with notify endpoint",
			upgradeAction: &fleetapi.ActionUpgrade{
				ActionType: fleetapi.ActionTypeUpgrade,
				Data: fleetapi.ActionUpgradeData{
					Version:   "255.0.0",
					SourceURI: "http://localhost",
				},
			},
			shouldProxyToEndpoint: true,
		},
		{
			name: "error from coordinator upgrade without notify endpoint",
			upgradeAction: &fleetapi.ActionUpgrade{
				ActionType: fleetapi.ActionTypeUpgrade,
				Data: fleetapi.ActionUpgradeData{
					Version:   "255.0.0",
					SourceURI: "http://localhost",
				},
			},
			coordUpgradeErr: errors.New("test error"),
		},
		{
			name: "no error from coordinator upgrade without notify endpoint",
			upgradeAction: &fleetapi.ActionUpgrade{
				ActionType: fleetapi.ActionTypeUpgrade,
				Data: fleetapi.ActionUpgradeData{
					Version:   "255.0.0",
					SourceURI: "http://localhost",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockCoordinator := newMockUpgradeCoordinator(t)

			var coordState coordinator.State
			if tc.shouldProxyToEndpoint {
				coordState.Components = []runtime.ComponentComponentState{
					{
						Component: component.Component{
							InputSpec: &component.InputRuntimeSpec{
								Spec: component.InputSpec{
									ProxiedActions: []string{fleetapi.ActionTypeUpgrade},
								},
							},
							InputType: "endpoint",
							Units: []component.Unit{
								{
									Type: client.UnitTypeInput,
									Config: &proto.UnitExpectedConfig{
										Type: "endpoint",
									},
								},
							},
						},
					},
				}

				mockCoordinator.EXPECT().State().Return(coordState)
			}

			upgradeCalledChan := make(chan struct{})
			if tc.shouldProxyToEndpoint {
				mockCoordinator.EXPECT().Upgrade(mock.Anything, tc.upgradeAction.Data.Version, tc.upgradeAction.Data.SourceURI, mock.Anything, mock.AnythingOfType("coordinator.UpgradeOpt"), mock.AnythingOfType("coordinator.UpgradeOpt")).
					RunAndReturn(func(ctx context.Context, s string, s2 string, actionUpgrade *fleetapi.ActionUpgrade, opt ...coordinator.UpgradeOpt) error {
						upgradeCalledChan <- struct{}{}
						return tc.coordUpgradeErr
					})
			} else {
				mockCoordinator.EXPECT().Upgrade(mock.Anything, tc.upgradeAction.Data.Version, tc.upgradeAction.Data.SourceURI, mock.Anything, mock.AnythingOfType("coordinator.UpgradeOpt")).
					RunAndReturn(func(ctx context.Context, s string, s2 string, actionUpgrade *fleetapi.ActionUpgrade, opt ...coordinator.UpgradeOpt) error {
						upgradeCalledChan <- struct{}{}
						return tc.coordUpgradeErr
					})
			}

			log, _ := logger.New("", false)
			u := NewUpgrade(log, mockCoordinator)
			u.tamperProtectionFn = func() bool { return tc.shouldProxyToEndpoint }

			notifyUnitsCalled := atomic.Bool{}
			u.notifyUnitsOfProxiedActionFn = func(ctx context.Context, log *logp.Logger, action dispatchableAction, ucs []unitWithComponent, performAction performActionFunc) error {
				notifyUnitsCalled.Store(true)
				return nil
			}

			ack := acker.NewMockAcker(t)

			if tc.coordUpgradeErr != nil {
				// on a coordinator upgrade error we should ack and commit all the bkg actions
				ack.EXPECT().Ack(mock.Anything, mock.Anything).Return(nil)
				ack.EXPECT().Commit(mock.Anything).Return(nil)
			}

			err := u.Handle(ctx, tc.upgradeAction, ack)
			require.NoError(t, err, "Handle should not return an error")

			select {
			case <-upgradeCalledChan:
				break
			case <-time.After(10 * time.Second):
				t.Fatal("mockCoordinator.Upgrade was not called in time")
			}

			// notifyUnitsOfProxiedActionFn should only ever be passed as a PreUpgradeCallback to the coordinator upgrader.
			// This assertion guards against it being called directly in this context.
			assert.False(t, notifyUnitsCalled.Load(), "notifyUnitsOfProxiedActionFn should not be called")

			assert.Eventually(t, func() bool {
				u.bkgMutex.Lock()
				defer u.bkgMutex.Unlock()
				if tc.coordUpgradeErr == nil {
					// yes this is counter-intuitive but when the coordinator upgrade returns a nil error
					// actions are not cleaned from bkgActions. This is most likely because after a successful upgrade
					// the expectation is for an agent to restart and thus the bkgActions will be lost.
					// NOTE if bkgActions gets to be persisted in the future this logic needs to change.
					return len(u.bkgActions) == 1
				} else {
					return len(u.bkgActions) == 0
				}
			}, 10*time.Second, 100*time.Millisecond)
		})
	}
}

type fakeAcker struct {
	mock.Mock
}

func (f *fakeAcker) Ack(ctx context.Context, action fleetapi.Action) error {
	args := f.Called(ctx, action)
	return args.Error(0)
}

func (f *fakeAcker) Commit(ctx context.Context) error {
	args := f.Called(ctx)
	return args.Error(0)
}
