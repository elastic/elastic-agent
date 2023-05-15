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

func (u *mockUpgradeManager) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, skipVerifyOverride bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {
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
	log, _ := logger.New("", false)
	ack := noopacker.New()
	agentInfo, _ := info.NewAgentInfo(true)
	msgChan := make(chan string)
	upgradeMgr := &mockUpgradeManager{msgChan: msgChan}
	specs := component.RuntimeSpecs{}
	c := coordinator.New(log, configuration.DefaultConfiguration(), logger.DefaultLogLevel, agentInfo, specs, nil, upgradeMgr, nil, nil, nil, nil, nil, false)
	u := NewUpgrade(log, c)
	ctx := context.Background()
	a := fleetapi.ActionUpgrade{Version: "8.3.0", SourceURI: "http://localhost"}
	err := u.Handle(ctx, &a, ack)
	require.NoError(t, err)
	msg := <-msgChan
	require.Equal(t, "completed 8.3.0", msg)
}

func TestUpgradeHandlerSameVersion(t *testing.T) {
	log, _ := logger.New("", false)
	ack := noopacker.New()
	agentInfo, _ := info.NewAgentInfo(true)
	msgChan := make(chan string)
	upgradeMgr := &mockUpgradeManager{msgChan: msgChan}
	specs := component.RuntimeSpecs{}
	c := coordinator.New(log, configuration.DefaultConfiguration(), logger.DefaultLogLevel, agentInfo, specs, nil, upgradeMgr, nil, nil, nil, nil, nil, false)
	u := NewUpgrade(log, c)
	ctx1 := context.Background()
	ctx2 := context.Background()
	a := fleetapi.ActionUpgrade{Version: "8.3.0", SourceURI: "http://localhost"}
	err1 := u.Handle(ctx1, &a, ack)
	err2 := u.Handle(ctx2, &a, ack)
	require.NoError(t, err1)
	require.NoError(t, err2)
	msg := <-msgChan
	require.Equal(t, "completed 8.3.0", msg)
}

func TestUpgradeHandlerNewVersion(t *testing.T) {
	log, _ := logger.New("", false)
	ack := noopacker.New()
	agentInfo, _ := info.NewAgentInfo(true)
	msgChan := make(chan string)
	upgradeMgr := &mockUpgradeManager{msgChan: msgChan}
	specs := component.RuntimeSpecs{}
	c := coordinator.New(log, configuration.DefaultConfiguration(), logger.DefaultLogLevel, agentInfo, specs, nil, upgradeMgr, nil, nil, nil, nil, nil, false)
	u := NewUpgrade(log, c)
	ctx1 := context.Background()
	ctx2 := context.Background()
	a1 := fleetapi.ActionUpgrade{Version: "8.2.0", SourceURI: "http://localhost"}
	a2 := fleetapi.ActionUpgrade{Version: "8.5.0", SourceURI: "http://localhost"}
	err1 := u.Handle(ctx1, &a1, ack)
	require.NoError(t, err1)
	time.Sleep(1 * time.Second)
	err2 := u.Handle(ctx2, &a2, ack)
	require.NoError(t, err2)
	msg1 := <-msgChan
	require.Equal(t, "canceled 8.2.0", msg1)
	msg2 := <-msgChan
	require.Equal(t, "completed 8.5.0", msg2)
}
