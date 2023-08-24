// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	noopacker "github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type mockUpgradeManager struct {
	msgChan chan string
}

func (u *mockUpgradeManager) Upgradeable() bool {
	return true
}

func (u *mockUpgradeManager) Reload(rawConfig *config.Config) error {
	return nil
}

func (u *mockUpgradeManager) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {
	select {
	case <-time.After(2 * time.Second):
		u.msgChan <- "completed " + version
		return nil, nil
	case <-ctx.Done():
		u.msgChan <- "canceled " + version
		return nil, ctx.Err()
	}
}

func (u *mockUpgradeManager) Ack(ctx context.Context, acker acker.Acker) error {
	return nil
}

func TestUpgradeHandler(t *testing.T) {
	// Create a cancellable context that will shut down the coordinator after
	// the test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log, _ := logger.New("", false)
	agentInfo, _ := info.NewAgentInfo(ctx, true)
	msgChan := make(chan string)

	// Create and start the coordinator
	c := coordinator.New(
		log,
		configuration.DefaultConfiguration(),
		logger.DefaultLogLevel,
		agentInfo,
		component.RuntimeSpecs{},
		nil,
		&mockUpgradeManager{msgChan: msgChan},
		nil, nil, nil, nil, nil, false)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a := fleetapi.ActionUpgrade{Version: "8.3.0", SourceURI: "http://localhost"}
	ack := noopacker.New()
	err := u.Handle(ctx, &a, ack)
	require.NoError(t, err)
	msg := <-msgChan
	require.Equal(t, "completed 8.3.0", msg)
}

func TestUpgradeHandlerSameVersion(t *testing.T) {
	// Create a cancellable context that will shut down the coordinator after
	// the test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log, _ := logger.New("", false)
	agentInfo, _ := info.NewAgentInfo(ctx, true)
	msgChan := make(chan string)

	// Create and start the Coordinator
	c := coordinator.New(
		log,
		configuration.DefaultConfiguration(),
		logger.DefaultLogLevel,
		agentInfo,
		component.RuntimeSpecs{},
		nil,
		&mockUpgradeManager{msgChan: msgChan},
		nil, nil, nil, nil, nil, false)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a := fleetapi.ActionUpgrade{Version: "8.3.0", SourceURI: "http://localhost"}
	ack := noopacker.New()
	err1 := u.Handle(ctx, &a, ack)
	err2 := u.Handle(ctx, &a, ack)
	require.NoError(t, err1)
	require.NoError(t, err2)
	msg := <-msgChan
	require.Equal(t, "completed 8.3.0", msg)
}

func TestUpgradeHandlerNewVersion(t *testing.T) {
	// Create a cancellable context that will shut down the coordinator after
	// the test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log, _ := logger.New("", false)
	agentInfo, _ := info.NewAgentInfo(ctx, true)
	msgChan := make(chan string)

	// Create and start the Coordinator
	c := coordinator.New(
		log,
		configuration.DefaultConfiguration(),
		logger.DefaultLogLevel,
		agentInfo,
		component.RuntimeSpecs{},
		nil,
		&mockUpgradeManager{msgChan: msgChan},
		nil, nil, nil, nil, nil, false)
	//nolint:errcheck // We don't need the termination state of the Coordinator
	go c.Run(ctx)

	u := NewUpgrade(log, c)
	a1 := fleetapi.ActionUpgrade{Version: "8.2.0", SourceURI: "http://localhost"}
	a2 := fleetapi.ActionUpgrade{Version: "8.5.0", SourceURI: "http://localhost"}
	ack := noopacker.New()
	err1 := u.Handle(ctx, &a1, ack)
	require.NoError(t, err1)
	time.Sleep(1 * time.Second)
	err2 := u.Handle(ctx, &a2, ack)
	require.NoError(t, err2)
	msg1 := <-msgChan
	require.Equal(t, "canceled 8.2.0", msg1)
	msg2 := <-msgChan
	require.Equal(t, "completed 8.5.0", msg2)
}
