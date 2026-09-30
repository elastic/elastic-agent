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
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	noopacker "github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

type mockUpgradeManager struct {
	UpgradeFn func(
		ctx context.Context,
		version string,
		sources []string,
		action *fleetapi.ActionUpgrade,
		details *details.Details,
		skipVerifyOverride bool,
		skipDefaultPgp bool,
		pgpBytes []string) (reexec.ShutdownCallbackFn, error)
}

func (u *mockUpgradeManager) Upgradeable() bool {
	return true
}

func (u *mockUpgradeManager) Reload(rawConfig *config.Config) error {
	return nil
}

func (u *mockUpgradeManager) Upgrade(ctx context.Context, version string, rollback bool, sources []string, action *fleetapi.ActionUpgrade, details *details.Details, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes []string, opts ...upgrade.Option) (reexec.ShutdownCallbackFn, error) {

	return u.UpgradeFn(
		ctx,
		version,
		sources,
		action,
		details,
		skipVerifyOverride,
		skipDefaultPgp,
		pgpBytes)
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
				sources []string,
				action *fleetapi.ActionUpgrade,
				details *details.Details,
				skipVerifyOverride bool,
				skipDefaultPgp bool,
				pgpBytes []string) (reexec.ShutdownCallbackFn, error) {

				upgradeCalledChan <- struct{}{}
				return nil, nil
			},
		},
		nil, nil, nil, nil, nil, false, nil, nil, nil)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a := fleetapi.ActionUpgrade{Data: fleetapi.ActionUpgradeData{
		Version: "8.3.0", Sources: []string{"http://localhost"}}}
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
				sources []string,
				action *fleetapi.ActionUpgrade,
				details *details.Details,
				skipVerifyOverride bool,
				skipDefaultPgp bool,
				pgpBytes []string) (reexec.ShutdownCallbackFn, error) {

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
		Version: "8.3.0", Sources: []string{"http://localhost"}}}
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
				sources []string,
				action *fleetapi.ActionUpgrade,
				details *details.Details,
				skipVerifyOverride bool,
				skipDefaultPgp bool,
				pgpBytes []string) (reexec.ShutdownCallbackFn, error) {

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
			Version: "8.5.0", Sources: []string{"http://localhost"},
		},
	}
	a2 := fleetapi.ActionUpgrade{
		ActionID: "action-8.5-2",
		Data: fleetapi.ActionUpgradeData{
			Version: "8.5.0", Sources: []string{"http://localhost"},
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
				sources []string,
				action *fleetapi.ActionUpgrade,
				details *details.Details,
				skipVerifyOverride bool,
				skipDefaultPgp bool,
				pgpBytes []string) (reexec.ShutdownCallbackFn, error) {

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
			Version: "8.2.0", Sources: []string{"http://localhost"},
		},
	}
	a2 := fleetapi.ActionUpgrade{
		ActionID: "action-8.5",
		Data: fleetapi.ActionUpgradeData{
			Version: "8.5.0", Sources: []string{"http://localhost"},
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
					Version: "255.0.0",
					Sources: []string{"http://localhost"},
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
					Version: "255.0.0",
					Sources: []string{"http://localhost"},
				},
			},
			shouldProxyToEndpoint: true,
		},
		{
			name: "error from coordinator upgrade without notify endpoint",
			upgradeAction: &fleetapi.ActionUpgrade{
				ActionType: fleetapi.ActionTypeUpgrade,
				Data: fleetapi.ActionUpgradeData{
					Version: "255.0.0",
					Sources: []string{"http://localhost"},
				},
			},
			coordUpgradeErr: errors.New("test error"),
		},
		{
			name: "no error from coordinator upgrade without notify endpoint",
			upgradeAction: &fleetapi.ActionUpgrade{
				ActionType: fleetapi.ActionTypeUpgrade,
				Data: fleetapi.ActionUpgradeData{
					Version: "255.0.0",
					Sources: []string{"http://localhost"},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockCoordinator := newMockUpgradeCoordinator(t)

			upgradeCalledChan := make(chan struct{})
			if tc.shouldProxyToEndpoint {
				// Tamper protection on → Upgrade receives rollback opt + pre-upgrade callback opt.
				mockCoordinator.EXPECT().Upgrade(mock.Anything, tc.upgradeAction.Data.Version, tc.upgradeAction.Data.Sources, mock.Anything, mock.AnythingOfType("coordinator.UpgradeOpt"), mock.AnythingOfType("coordinator.UpgradeOpt")).
					RunAndReturn(func(ctx context.Context, v string, s []string, actionUpgrade *fleetapi.ActionUpgrade, opt ...coordinator.UpgradeOpt) error {
						upgradeCalledChan <- struct{}{}
						return tc.coordUpgradeErr
					})
			} else {
				// Tamper protection off → Upgrade receives rollback opt only.
				mockCoordinator.EXPECT().Upgrade(mock.Anything, tc.upgradeAction.Data.Version, tc.upgradeAction.Data.Sources, mock.Anything, mock.AnythingOfType("coordinator.UpgradeOpt")).
					RunAndReturn(func(ctx context.Context, v string, s []string, actionUpgrade *fleetapi.ActionUpgrade, opt ...coordinator.UpgradeOpt) error {
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

// TestNotifyEndpointOfUpgrade verifies that notifyEndpointOfUpgrade waits for
// the endpoint component to appear in the coordinator state before dispatching
// the action. This covers the startup race where an upgrade action fires before
// the policy has been applied and Endpoint is not yet present in State().Components.
func TestNotifyEndpointOfUpgrade(t *testing.T) {
	const endpointComponentID = "endpoint-default"

	endpointState := coordinator.State{
		PolicyApplied: true,
		PolicyConfiguredActionTypes: map[string][]string{
			fleetapi.ActionTypeUpgrade: {endpointComponentID},
		},
		Components: []runtime.ComponentComponentState{
			{
				Component: component.Component{
					ID: endpointComponentID,
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
		},
	}

	// policyAppliedNoUnits simulates the window where the policy has been processed
	// but Endpoint has not yet emitted its first runtime state update (Components is
	// empty). PolicyConfiguredActionTypes is set from the policy model so the handler
	// knows to wait rather than skip.
	policyAppliedNoUnits := coordinator.State{
		PolicyApplied: true,
		PolicyConfiguredActionTypes: map[string][]string{
			fleetapi.ActionTypeUpgrade: {endpointComponentID},
		},
	}

	for _, tc := range []struct {
		name          string
		stateSequence []coordinator.State // successive State() calls return these in order
		wantNotified  bool
	}{
		{
			name: "endpoint already connected — notified on first poll",
			stateSequence: []coordinator.State{
				endpointState,
			},
			wantNotified: true,
		},
		{
			name: "upgrade fires before policy applied — notified once policy and units appear",
			stateSequence: []coordinator.State{
				{}, // policy not applied yet
				{}, // still empty
				endpointState,
			},
			wantNotified: true,
		},
		{
			name: "policy applied but endpoint not yet in Components — notified once units appear",
			stateSequence: []coordinator.State{
				policyAppliedNoUnits, // endpoint in policy, but no runtime state yet
				policyAppliedNoUnits, // still no units
				endpointState,
			},
			wantNotified: true,
		},
		{
			name: "endpoint not in policy — skipped immediately once policy applied",
			stateSequence: []coordinator.State{
				{},                    // policy not applied yet
				{PolicyApplied: true}, // policy applied, endpoint not in PolicyConfiguredActionTypes
			},
			wantNotified: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockCoord := newMockUpgradeCoordinator(t)

			callIdx := 0
			mockCoord.EXPECT().State().RunAndReturn(func() coordinator.State {
				idx := callIdx
				if idx >= len(tc.stateSequence) {
					idx = len(tc.stateSequence) - 1
				}
				callIdx++
				return tc.stateSequence[idx]
			}).Times(len(tc.stateSequence))

			if tc.wantNotified {
				mockCoord.EXPECT().PerformAction(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, nil).Maybe()
			}

			log, _ := logger.New("", false)
			u := NewUpgrade(log, mockCoord)
			u.endpointWaitTimeout = 5 * time.Second
			u.endpointPollInterval = 1 * time.Millisecond

			notified := atomic.Bool{}
			u.notifyUnitsOfProxiedActionFn = func(_ context.Context, _ *logp.Logger, _ dispatchableAction, _ []unitWithComponent, _ performActionFunc) error {
				notified.Store(true)
				return nil
			}

			action := &fleetapi.ActionUpgrade{
				ActionType: fleetapi.ActionTypeUpgrade,
				Data:       fleetapi.ActionUpgradeData{Version: "9.0.0"},
			}

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			err := u.notifyEndpointOfUpgrade(ctx, log, action)
			require.NoError(t, err)
			assert.Equal(t, tc.wantNotified, notified.Load())
		})
	}

	t.Run("parent context cancelled — error propagated, no dispatch", func(t *testing.T) {
		mockCoord := newMockUpgradeCoordinator(t)
		// State() is called once before the select fires on the cancelled context.
		// Poll interval is set to 1h so the ticker never competes with timeoutCtx.Done().
		mockCoord.EXPECT().State().Return(coordinator.State{}).Times(1)

		log, _ := logger.New("", false)
		u := NewUpgrade(log, mockCoord)
		u.endpointWaitTimeout = 5 * time.Second
		u.endpointPollInterval = 1 * time.Hour

		notified := atomic.Bool{}
		u.notifyUnitsOfProxiedActionFn = func(_ context.Context, _ *logp.Logger, _ dispatchableAction, _ []unitWithComponent, _ performActionFunc) error {
			notified.Store(true)
			return nil
		}

		action := &fleetapi.ActionUpgrade{
			ActionType: fleetapi.ActionTypeUpgrade,
			Data:       fleetapi.ActionUpgradeData{Version: "9.0.0"},
		}

		ctx, cancel := context.WithCancel(t.Context())
		cancel() // cancel before calling — timeoutCtx inherits the cancellation

		err := u.notifyEndpointOfUpgrade(ctx, log, action)
		require.ErrorIs(t, err, context.Canceled)
		assert.False(t, notified.Load())
	})
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
