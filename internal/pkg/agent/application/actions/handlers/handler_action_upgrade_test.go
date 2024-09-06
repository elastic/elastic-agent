// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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

func (u *mockUpgradeManager) Upgrade(
	ctx context.Context,
	version string,
	sourceURI string,
	action *fleetapi.ActionUpgrade,
	details *details.Details,
	skipVerifyOverride bool,
	skipDefaultPgp bool,
	pgpBytes ...string) (reexec.ShutdownCallbackFn, error) {

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

func (u *mockUpgradeManager) Ack(ctx context.Context, acker acker.Acker) error {
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
		nil, nil, nil, nil, nil, false)
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
	case <-time.Tick(50 * time.Millisecond):
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
		nil, nil, nil, nil, nil, false)
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
	case <-time.Tick(50 * time.Millisecond):
		t.Fatal("mockUpgradeManager.Upgrade was not called")
	case <-upgradeCalledChan:
	}
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
		nil, nil, nil, nil, nil, false)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a1 := fleetapi.ActionUpgrade{Data: fleetapi.ActionUpgradeData{
		Version: "8.2.0", SourceURI: "http://localhost"}}
	a2 := fleetapi.ActionUpgrade{Data: fleetapi.ActionUpgradeData{
		Version: "8.5.0", SourceURI: "http://localhost"}}
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
