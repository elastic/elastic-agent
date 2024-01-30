// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // duplicate code is in test cases
package runtime

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.elastic.co/apm/apmtest"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestManager_SimpleComponentErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(
		newDebugLogger(t),
		newDebugLogger(t),
		"localhost:0",
		ai,
		apmtest.DiscardTracer,
		newTestMonitoringMgr(),
		configuration.DefaultGRPCConfig(),
	)
	require.NoError(t, err)

	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := waitForReady(waitCtx, m); err != nil {
		require.NoError(t, err)
	}

	comp := component.Component{
		ID:  "error-default",
		Err: errors.New("hard-coded error"),
		Units: []component.Unit{
			{
				ID:     "error-input",
				Type:   client.UnitTypeInput,
				Config: nil,
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "error-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateStarting {
					// initial is starting
				} else if state.State == client.UnitStateFailed {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "error-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							// should be failed
							subErrCh <- nil
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					}
				} else {
					subErrCh <- fmt.Errorf("component reported unexpected state: %v", state.State)
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	m.Update(component.Model{Components: []component.Component{comp}})
	err = <-m.errCh
	require.NoError(t, err)

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func newDebugLogger(t *testing.T) *logger.Logger {
	t.Helper()

	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.DebugLevel
	loggerCfg.ToStderr = true

	log, err := logger.NewFromConfig("", loggerCfg, false)
	require.NoError(t, err)
	return log
}

func drainErrChan(ch chan error) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

type testMonitoringManager struct{}

func newTestMonitoringMgr() *testMonitoringManager { return &testMonitoringManager{} }

func (*testMonitoringManager) EnrichArgs(_ string, _ string, args []string) []string { return args }
func (*testMonitoringManager) Prepare(_ string) error                                { return nil }
func (*testMonitoringManager) Cleanup(string) error                                  { return nil }

// waitForReady waits until the RPC server is ready to be used.
func waitForReady(ctx context.Context, m *Manager) error {
	for !m.serverReady.Load() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}
