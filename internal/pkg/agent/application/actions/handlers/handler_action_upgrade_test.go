// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
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
	msgChan     chan string
	successChan chan string
	errChan     chan error
}

func (u *mockUpgradeManager) Upgradeable() bool {
	return true
}

func (u *mockUpgradeManager) Reload(rawConfig *config.Config) error {
	return nil
}

func (u *mockUpgradeManager) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, details *details.Details, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {
	select {
	case msg := <-u.successChan:
		u.msgChan <- msg
		return nil, nil
	case err := <-u.errChan:
		u.msgChan <- err.Error()
		return nil, ctx.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
	msgChan := make(chan string)
	completedChan := make(chan string)

	// Create and start the coordinator
	c := coordinator.New(
		log,
		configuration.DefaultConfiguration(),
		logger.DefaultLogLevel,
		agentInfo,
		component.RuntimeSpecs{},
		nil,
		&mockUpgradeManager{msgChan: msgChan, successChan: completedChan},
		nil, nil, nil, nil, nil, false)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a := fleetapi.ActionUpgrade{Data: fleetapi.ActionUpgradeData{
		Version: "8.3.0", SourceURI: "http://localhost"}}
	ack := noopacker.New()
	err := u.Handle(ctx, &a, ack)
	// indicate that upgrade is completed
	close(completedChan)
	require.NoError(t, err)
	msg := <-msgChan
	require.Equal(t, "completed 8.3.0", msg)
}

func TestUpgradeHandlerSameVersion(t *testing.T) {
	// Create a cancellable context that will shut down the coordinator after
	// the test.
	logp.DevelopmentSetup()
	logger.SetLevel(logp.DebugLevel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log, _ := logger.New("", false)

	agentInfo := &info.AgentInfo{}
	msgChan := make(chan string)
	successChan := make(chan string)
	errChan := make(chan error)

	// Create and start the Coordinator
	c := coordinator.New(
		log,
		configuration.DefaultConfiguration(),
		logger.DefaultLogLevel,
		agentInfo,
		component.RuntimeSpecs{},
		nil,
		&mockUpgradeManager{msgChan: msgChan, successChan: successChan, errChan: errChan},
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

	successChan <- "completed 8.3.0"
	require.Equal(t, "completed 8.3.0", <-msgChan)
	errChan <- errors.New("duplicated update, not finishing it?")
	require.Equal(t, "duplicated update, not finishing it?", <-msgChan)

}

func TestUpgradeHandlerNewVersion(t *testing.T) {
	// Create a cancellable context that will shut down the coordinator after
	// the test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log, _ := logger.New("", false)

	agentInfo := &info.AgentInfo{}
	msgChan := make(chan string)
	completedChan := make(chan string)
	errorChan := make(chan error)

	// Create and start the Coordinator
	c := coordinator.New(
		log,
		configuration.DefaultConfiguration(),
		logger.DefaultLogLevel,
		agentInfo,
		component.RuntimeSpecs{},
		nil,
		&mockUpgradeManager{msgChan: msgChan, successChan: completedChan, errChan: errorChan},
		nil, nil, nil, nil, nil, false)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a1 := fleetapi.ActionUpgrade{Data: fleetapi.ActionUpgradeData{
		Version: "8.2.0", SourceURI: "http://localhost"}}
	a2 := fleetapi.ActionUpgrade{Data: fleetapi.ActionUpgradeData{
		Version: "8.5.0", SourceURI: "http://localhost"}}
	ack := noopacker.New()

	// Send both upgrade actions, a1 will error before a2 succeeds
	err1 := u.Handle(ctx, &a1, ack)
	require.NoError(t, err1)
	err2 := u.Handle(ctx, &a2, ack)
	require.NoError(t, err2)

	// Send an error so the first action is "cancelled"
	errorChan <- errors.New("cancelled 8.2.0")
	// Wait for the mockUpgradeHandler to receive and "process" the error
	require.Equal(t, "cancelled 8.2.0", <-msgChan, "mockUpgradeHandler.Upgrade did not receive the expected error")

	// Send a success so the second action succeeds
	completedChan <- "completed 8.5.0"
	require.Equal(t, "completed 8.5.0", <-msgChan, "mockUpgradeHandler.Upgrade did not receive the success signal")
}
