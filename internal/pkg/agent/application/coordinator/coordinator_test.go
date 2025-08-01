// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent-libs/mapstr"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.elastic.co/apm/v2/apmtest"
	"go.opentelemetry.io/collector/confmap"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	exeExt = ".exe"
)

var (
	fakeInputSpec = component.InputSpec{
		Name:      "fake",
		Platforms: []string{fmt.Sprintf("%s/%s", goruntime.GOOS, goruntime.GOARCH)},
		Outputs:   []string{"fake-output"},
		Command: &component.CommandSpec{
			Timeouts: component.CommandTimeoutSpec{
				Checkin: 30 * time.Second,
				Restart: 10 * time.Millisecond, // quick restart during tests
				Stop:    30 * time.Second,
			},
		},
	}
	fakeIsolatedUnitsInputSpec = component.InputSpec{
		Name:      "fake-isolated-units",
		Platforms: []string{fmt.Sprintf("%s/%s", goruntime.GOOS, goruntime.GOARCH)},
		Outputs:   []string{"fake-output"},
		Command: &component.CommandSpec{
			Timeouts: component.CommandTimeoutSpec{
				Checkin: 30 * time.Second,
				Restart: 10 * time.Millisecond, // quick restart during tests
				Stop:    30 * time.Second,
			},
		},
		IsolateUnits: true,
	}
)

// waitForState listens on the given stateChan for a state where stateCallback
// returns true, up to the given timeout duration, and reports a test failure
// if it doesn't arrive.
func waitForState(
	t testing.TB,
	stateChan chan State,
	stateCallback func(State) bool,
	timeout time.Duration,
) {
	t.Helper()
	timeoutChan := time.After(timeout)
	for {
		select {
		case state := <-stateChan:
			if stateCallback(state) {
				return
			}
		case <-timeoutChan:
			require.Fail(t, "timed out waiting for expected state")
			return
		}
	}
}

func TestComponentUpdateDiff(t *testing.T) {

	observedCore, observedLogs := observer.New(zapcore.DebugLevel)
	err := logp.ConfigureWithOutputs(logp.Config{
		Level:      logp.DebugLevel,
		ToStderr:   false,
		ToSyslog:   false,
		ToFiles:    false,
		ToEventLog: false,
	}, observedCore)
	require.NoError(t, err)

	cases := []struct {
		name    string
		old     []component.Component
		new     []component.Component
		logtest func(t *testing.T, logs UpdateStats)
	}{
		{
			name: "test-basic-removed",
			old: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
				},
				{
					ID:         "component-two",
					OutputType: "kafka",
				},
			},
			new: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
				},
			},
			logtest: func(t *testing.T, logs UpdateStats) {

				require.Equal(t, []string{"component-two"}, logs.Components.Removed)
				require.Equal(t, []string{"kafka"}, logs.Outputs.Removed)
			},
		},
		{
			name: "test-added-and-removed",
			old: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
				},
				{
					ID:         "component-two",
					OutputType: "kafka",
				},
			},
			new: []component.Component{
				{
					ID:         "component-three",
					OutputType: "elasticsearch",
				},
			},
			logtest: func(t *testing.T, logs UpdateStats) {
				require.Equal(t, 2, len(logs.Components.Removed))
				require.Equal(t, []string{"component-three"}, logs.Components.Added)
				require.Equal(t, []string{"kafka"}, logs.Outputs.Removed)
			},
		},
		{
			name: "test-updated-component",
			old: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
					Units: []component.Unit{
						{ID: "unit-one"},
						{ID: "unit-two"},
						{ID: "unit-x"},
					},
				},
			},
			new: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
					Units: []component.Unit{
						{ID: "unit-one"},
						{ID: "unit-two"},
						{ID: "unit-three"},
					},
				},
			},
			logtest: func(t *testing.T, logs UpdateStats) {
				require.Contains(t, logs.Components.Updated[0], "unit-three: added")
				require.Contains(t, logs.Components.Updated[0], "unit-x: removed")
			},
		},
		{
			name: "just-change-output",
			old: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
				},
			},
			new: []component.Component{
				{
					ID:         "component-one",
					OutputType: "logstash",
				},
			},
			logtest: func(t *testing.T, logs UpdateStats) {
				require.Equal(t, []string{"elasticsearch"}, logs.Outputs.Removed)
				require.Equal(t, []string{"logstash"}, logs.Outputs.Added)
			},
		},
		{
			name: "config-update",
			old: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
					Units: []component.Unit{
						{
							ID:     "unit-one",
							Config: &proto.UnitExpectedConfig{Source: mustNewStruct(t, map[string]interface{}{"example": "value"})},
						},
					},
				},
			},
			new: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
					Units: []component.Unit{
						{
							ID:     "unit-one",
							Config: &proto.UnitExpectedConfig{Source: mustNewStruct(t, map[string]interface{}{"example": "two"})},
						},
					},
				},
			},
			logtest: func(t *testing.T, logs UpdateStats) {
				require.NotEmpty(t, logs.Components.Updated)
			},
		},
		{
			name: "config-no-changes",
			old: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
					Units: []component.Unit{
						{
							ID:     "unit-one",
							Config: &proto.UnitExpectedConfig{Source: mustNewStruct(t, map[string]interface{}{"example": "value"})},
						},
					},
				},
			},
			new: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
					Units: []component.Unit{
						{
							ID:     "unit-one",
							Config: &proto.UnitExpectedConfig{Source: mustNewStruct(t, map[string]interface{}{"example": "value"})},
						},
					},
				},
			},
			logtest: func(t *testing.T, logs UpdateStats) {
				require.Len(t, logs.Components.Updated, 0)
			},
		},
		{
			name: "config-source-nil",
			old: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
					Units: []component.Unit{
						{
							ID:     "unit-one",
							Config: &proto.UnitExpectedConfig{Id: "test"},
						},
					},
				},
			},
			new: []component.Component{
				{
					ID:         "component-one",
					OutputType: "elasticsearch",
					Units: []component.Unit{
						{
							ID:     "unit-one",
							Config: &proto.UnitExpectedConfig{Id: "test"},
						},
					},
				},
			},
			logtest: func(t *testing.T, logs UpdateStats) {
				require.Len(t, logs.Components.Updated, 0)
			},
		},
	}

	for _, testcase := range cases {

		t.Run(testcase.name, func(t *testing.T) {
			testCoord := Coordinator{
				logger:         logp.L(),
				componentModel: testcase.new,
			}
			testCoord.checkAndLogUpdate(testcase.old)

			obsLogs := observedLogs.All()
			last := obsLogs[len(obsLogs)-1]

			// extract the structured data from the log message
			testcase.logtest(t, last.Context[0].Interface.(UpdateStats))
		})
	}
}

func mustNewStruct(t *testing.T, v map[string]interface{}) *structpb.Struct {
	str, err := structpb.NewStruct(v)
	require.NoError(t, err)
	return str
}

func TestCoordinator_VarsMgr_Observe(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t, ctx)
	stateChan := coord.StateSubscribe(ctx, 32)
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	// wait for it to be in starting state
	waitForState(t, stateChan, func(state State) bool {
		return state.State == agentclient.Starting &&
			state.Message == "Waiting for initial configuration and composable variables"
	}, 3*time.Second)

	// set vars state should stay same (until config)
	varsMgr.Vars(ctx, []*transpiler.Vars{{}})

	// State changes happen asynchronously in the Coordinator goroutine, so
	// wait a little bit to make sure no changes are reported; if the Vars
	// call does trigger a change, it should happen relatively quickly.
	select {
	case <-stateChan:
		assert.Fail(t, "Vars call shouldn't cause a state change")
	case <-time.After(50 * time.Millisecond):
	}

	// set configuration that has variables present
	cfg, err := config.NewConfigFrom(map[string]interface{}{
		"inputs": []interface{}{
			map[string]interface{}{
				"type": "filestream",
				"paths": []interface{}{
					"${env.filestream_path|env.log_path|'/var/log/syslog'}",
				},
			},
			map[string]interface{}{
				"type":      "windows",
				"condition": "${host.platform} == 'windows'",
			},
		},
	})
	require.NoError(t, err)
	cfgMgr.Config(ctx, cfg)

	// healthy signals that the configuration has been computed
	waitForState(t, stateChan, func(state State) bool {
		return state.State == agentclient.Healthy && state.Message == "Running"
	}, 3*time.Second)

	// get the set observed vars from the fake vars manager
	varsMgr.observedMx.Lock()
	observed := varsMgr.observed
	varsMgr.observedMx.Unlock()

	// stop the coordinator
	cancel()
	err = <-coordCh
	require.NoError(t, err)

	// verify that the observed vars are the expected vars
	assert.Equal(t, []string{"env.filestream_path", "env.log_path", "host.platform"}, observed)
}

func TestCoordinator_State_Starting(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t, ctx)
	stateChan := coord.StateSubscribe(ctx, 32)
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	waitForState(t, stateChan, func(state State) bool {
		return state.State == agentclient.Starting &&
			state.Message == "Waiting for initial configuration and composable variables"
	}, 3*time.Second)

	// set vars state should stay same (until config)
	varsMgr.Vars(ctx, []*transpiler.Vars{{}})

	// State changes happen asynchronously in the Coordinator goroutine, so
	// wait a little bit to make sure no changes are reported; if the Vars
	// call does trigger a change, it should happen relatively quickly.
	select {
	case <-stateChan:
		assert.Fail(t, "Vars call shouldn't cause a state change")
	case <-time.After(50 * time.Millisecond):
	}

	// set configuration should change to healthy
	cfg, err := config.NewConfigFrom(nil)
	require.NoError(t, err)
	cfgMgr.Config(ctx, cfg)

	waitForState(t, stateChan, func(state State) bool {
		return state.State == agentclient.Healthy && state.Message == "Running"
	}, 3*time.Second)

	cancel()
	err = <-coordCh
	require.NoError(t, err)
}

func TestCoordinator_State_ConfigError_NotManaged(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t, ctx)
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	// no vars used by the config
	varsMgr.Vars(ctx, []*transpiler.Vars{{}})

	// no configuration needed
	cfg, err := config.NewConfigFrom(nil)
	require.NoError(t, err)
	cfgMgr.Config(ctx, cfg)

	// set an error on cfg manager
	const errorStr = "force error"
	cfgMgr.ReportError(ctx, errors.New(errorStr))
	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Failed && strings.Contains(state.Message, "force error")
	}, 3*time.Second, 10*time.Millisecond)

	// clear error
	cfgMgr.ReportError(ctx, nil)
	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Healthy && state.Message == "Running"
	}, 3*time.Second, 10*time.Millisecond)

	cancel()
	err = <-coordCh
	require.NoError(t, err)
}

func TestUpgradeSameErrorAcked(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	upgradeManager := &fakeUpgradeManager{
		upgradeable: true,
		upgradeErr:  upgrade.ErrUpgradeSameVersion,
	}

	acker := &fakeActionAcker{}
	coord, _, _ := createCoordinator(t, ctx,
		ManagedCoordinator(true),
		WithUpgradeManager(upgradeManager),
		WithActionAcker(acker))

	var coordWait sync.WaitGroup
	coordWait.Add(1)
	go func() {
		coordWait.Done()
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	coordWait.Wait()

	action := fleetapi.NewAction(fleetapi.ActionTypeUpgrade)
	actionUpgrade, ok := action.(*fleetapi.ActionUpgrade)
	require.True(t, ok)

	acker.On("Ack", mock.Anything, actionUpgrade).Return(nil)

	require.NoError(t, coord.Upgrade(t.Context(), "9.0", "http://localhost", actionUpgrade, true, true))

	acker.AssertCalled(t, "Ack", mock.Anything, actionUpgrade)
}

func TestCoordinator_State_ConfigError_Managed(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t, ctx, ManagedCoordinator(true))
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	// no vars used by the config
	varsMgr.Vars(ctx, []*transpiler.Vars{{}})

	// no configuration needed
	cfg, err := config.NewConfigFrom(nil)
	require.NoError(t, err)
	cfgMgr.Config(ctx, cfg)

	// set an error on cfg manager
	cfgMgr.ReportError(ctx, errors.New("force error"))
	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Healthy && state.Message == "Running" && state.FleetState == agentclient.Failed && state.FleetMessage == "force error"
	}, 3*time.Second, 10*time.Millisecond)

	// clear error
	cfgMgr.ReportError(ctx, nil)
	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Healthy && state.Message == "Running" && state.FleetState == agentclient.Healthy && state.FleetMessage == "Connected"
	}, 3*time.Second, 10*time.Millisecond)

	// report a warning
	cfgMgr.ReportError(ctx, NewWarningError("some msg from Fleet"))
	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Healthy && state.Message == "Running" && state.FleetState == agentclient.Degraded && state.FleetMessage == "some msg from Fleet"
	}, 3*time.Second, 10*time.Millisecond)

	// recover from warning error
	cfgMgr.ReportError(ctx, nil)
	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Healthy && state.Message == "Running" && state.FleetState == agentclient.Healthy && state.FleetMessage == "Connected"
	}, 3*time.Second, 10*time.Millisecond)

	cancel()
	err = <-coordCh
	require.NoError(t, err)
}

func TestCoordinator_StateSubscribe(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t, ctx)
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	resultChan := make(chan error)
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		subChan := coord.StateSubscribe(ctx, 32)
		for {
			select {
			case <-ctx.Done():
				resultChan <- ctx.Err()
				return
			case state := <-subChan:
				t.Logf("%+v", state)
				compState := getComponentState(state.Components, "fake-default")
				if compState != nil {
					unit, ok := compState.State.Units[runtime.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-fake"}]
					if ok {
						if unit.State == client.UnitStateHealthy && unit.Message == "Healthy From Fake Config" {
							resultChan <- nil
							return
						}
					}
				}
			}
		}
	}()

	// no vars used by the config
	varsMgr.Vars(ctx, []*transpiler.Vars{{}})

	// set the configuration to run a fake input
	cfg, err := config.NewConfigFrom(map[string]interface{}{
		"outputs": map[string]interface{}{
			"default": map[string]interface{}{
				"type": "fake-output",
			},
		},
		"inputs": []interface{}{
			map[string]interface{}{
				"type":       "fake",
				"use_output": "default",
				"state":      client.UnitStateHealthy,
				"message":    "Healthy From Fake Config",
			},
		},
	})
	require.NoError(t, err)
	cfgMgr.Config(ctx, cfg)

	err = <-resultChan
	require.NoError(t, err)
	cancel()

	err = <-coordCh
	require.NoError(t, err)
}

func TestCoordinator_StateSubscribeIsolatedUnits(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t, ctx, WithComponentInputSpec(fakeIsolatedUnitsInputSpec))
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	resultChan := make(chan error)
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		subChan := coord.StateSubscribe(ctx, 32)
		for {
			select {
			case <-ctx.Done():
				resultChan <- ctx.Err()
				return
			case state := <-subChan:
				if len(state.Components) == 2 {
					compState0 := getComponentState(state.Components, "fake-isolated-units-default-fake-isolated-units-0")
					compState1 := getComponentState(state.Components, "fake-isolated-units-default-fake-isolated-units-1")
					if compState0 != nil && compState1 != nil {
						unit0, ok0 := compState0.State.Units[runtime.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-isolated-units-default-fake-isolated-units-0-unit"}]
						unit1, ok1 := compState1.State.Units[runtime.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-isolated-units-default-fake-isolated-units-1-unit"}]
						if ok0 && ok1 {
							if (unit0.State == client.UnitStateHealthy && unit0.Message == "Healthy From Fake Isolated Units 0 Config") &&
								(unit1.State == client.UnitStateHealthy && unit1.Message == "Healthy From Fake Isolated Units 1 Config") {
								resultChan <- nil
								return
							} else if unit0.State == client.UnitStateFailed && unit1.State == client.UnitStateFailed {
								// if you get a really strange failed state, check to make sure the mock binaries in
								// elastic-agent/pkg/component/fake/ are updated
								t.Fail()
								t.Logf("got units with failed state: %#v / %#v", unit1, unit0)
							}
						}
					}
				}
			}
		}
	}()

	// no vars used by the config
	varsMgr.Vars(ctx, []*transpiler.Vars{{}})

	// set the configuration to run a fake input
	cfg, err := config.NewConfigFrom(map[string]interface{}{
		"outputs": map[string]interface{}{
			"default": map[string]interface{}{
				"type": "fake-output",
			},
		},
		"inputs": []interface{}{
			map[string]interface{}{
				"id":         "fake-isolated-units-0",
				"type":       "fake-isolated-units",
				"use_output": "default",
				"state":      client.UnitStateHealthy,
				"message":    "Healthy From Fake Isolated Units 0 Config",
			},
			map[string]interface{}{
				"id":         "fake-isolated-units-1",
				"type":       "fake-isolated-units",
				"use_output": "default",
				"state":      client.UnitStateHealthy,
				"message":    "Healthy From Fake Isolated Units 1 Config",
			},
		},
	})
	require.NoError(t, err)
	cfgMgr.Config(ctx, cfg)

	err = <-resultChan
	require.NoError(t, err)
	cancel()

	err = <-coordCh
	require.NoError(t, err)
}

func TestCollectManagerErrorsTimeout(t *testing.T) {
	handlerChan, _, _, _, _, _ := setupManagerShutdownChannels(time.Millisecond)
	// Don't send anything to the shutdown channels, causing a timeout
	// in collectManagerErrors
	waitAndTestError(t, func(err error) bool {
		return err != nil &&
			strings.Contains(err.Error(), "timeout while waiting for managers")
	}, handlerChan)
}

func TestCollectManagerErrorsOneResponse(t *testing.T) {
	handlerChan, _, _, config, _, _ := setupManagerShutdownChannels(10 * time.Millisecond)

	// Send an error for the config manager -- we should also get a
	// timeout error since we don't send anything on the other two channels.
	cfgErrStr := "config watcher error"
	config <- errors.New(cfgErrStr)

	waitAndTestError(t, func(err error) bool {
		return err != nil &&
			strings.Contains(err.Error(), cfgErrStr) &&
			strings.Contains(err.Error(), "timeout while waiting for managers")
	}, handlerChan)
}

func TestCollectManagerErrorsAllResponses(t *testing.T) {
	handlerChan, runtime, varWatcher, config, otel, upgradeMarkerWatcher := setupManagerShutdownChannels(5 * time.Second)
	runtimeErrStr := "runtime error"
	varsErrStr := "vars error"
	otelErrStr := "otel error"
	upgradeMarkerWatcherErrStr := "upgrade marker watcher error"
	runtime <- errors.New(runtimeErrStr)
	varWatcher <- errors.New(varsErrStr)
	config <- nil
	otel <- errors.New(otelErrStr)
	upgradeMarkerWatcher <- errors.New(upgradeMarkerWatcherErrStr)

	waitAndTestError(t, func(err error) bool {
		return err != nil &&
			strings.Contains(err.Error(), runtimeErrStr) &&
			strings.Contains(err.Error(), varsErrStr) &&
			strings.Contains(err.Error(), otelErrStr) &&
			strings.Contains(err.Error(), upgradeMarkerWatcherErrStr)
	}, handlerChan)
}

func TestCollectManagerErrorsAllResponsesNoErrors(t *testing.T) {
	handlerChan, runtime, varWatcher, config, otel, upgradeMarkerWatcher := setupManagerShutdownChannels(5 * time.Second)
	runtime <- nil
	varWatcher <- nil
	config <- context.Canceled
	otel <- nil
	upgradeMarkerWatcher <- nil

	// All errors are nil or context.Canceled, so collectManagerErrors
	// should also return nil.

	waitAndTestError(t, func(err error) bool {
		return err == nil
	}, handlerChan)
}

func waitAndTestError(t *testing.T, check func(error) bool, handlerErr chan error) {
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second*4)
	defer waitCancel()
	for {
		select {
		case <-waitCtx.Done():
			t.Fatalf("timed out while waiting for response from collectManagerErrors")
		case gotErr := <-handlerErr:
			if handlerErr != nil {
				if check(gotErr) {
					t.Logf("got correct error")
					return
				} else {
					t.Fatalf("got incorrect error: %s", gotErr)
				}
			}
		}
	}
}

func setupManagerShutdownChannels(timeout time.Duration) (chan error, chan error, chan error, chan error, chan error, chan error) {
	runtime := make(chan error)
	varWatcher := make(chan error)
	config := make(chan error)
	otelWatcher := make(chan error)
	upgradeMarkerWatcher := make(chan error)

	handlerChan := make(chan error)
	go func() {
		handlerErr := collectManagerErrors(timeout, varWatcher, runtime, config, otelWatcher, upgradeMarkerWatcher)
		handlerChan <- handlerErr
	}()

	return handlerChan, runtime, varWatcher, config, otelWatcher, upgradeMarkerWatcher
}

func TestCoordinator_ReExec(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t, ctx)
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	// no vars used by the config
	varsMgr.Vars(ctx, []*transpiler.Vars{{}})

	// no need for anything to really run
	cfg, err := config.NewConfigFrom(nil)
	require.NoError(t, err)
	cfgMgr.Config(ctx, cfg)

	called := false
	coord.ReExec(func() error {
		called = true
		return nil
	})
	assert.True(t, called)
	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Stopping && state.Message == "Re-executing"
	}, 3*time.Second, 10*time.Millisecond)
	cancel()

	err = <-coordCh
	require.NoError(t, err)
}

func TestCoordinator_Upgrade(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t, ctx)
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	// no vars used by the config
	varsMgr.Vars(ctx, []*transpiler.Vars{{}})

	// no need for anything to really run
	cfg, err := config.NewConfigFrom(nil)
	require.NoError(t, err)
	cfgMgr.Config(ctx, cfg)

	err = coord.Upgrade(ctx, "9.0.0", "", nil, true, false)
	require.ErrorIs(t, err, ErrNotUpgradable)
	cancel()

	err = <-coordCh
	require.NoError(t, err)
}

func TestCoordinator_UpgradeDetails(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	expectedErr := errors.New("some upgrade error")
	upgradeManager := &fakeUpgradeManager{
		upgradeable: true,
		upgradeErr:  expectedErr,
	}
	coord, cfgMgr, varsMgr := createCoordinator(t, ctx, WithUpgradeManager(upgradeManager))
	require.Nil(t, coord.state.UpgradeDetails)
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	// no vars used by the config
	varsMgr.Vars(ctx, []*transpiler.Vars{{}})

	// no need for anything to really run
	cfg, err := config.NewConfigFrom(nil)
	require.NoError(t, err)
	cfgMgr.Config(ctx, cfg)

	err = coord.Upgrade(ctx, "9.0.0", "", nil, true, false)
	require.ErrorIs(t, expectedErr, err)
	cancel()

	err = <-coordCh
	require.NoError(t, err)

	require.Equal(t, details.StateFailed, coord.state.UpgradeDetails.State)
	require.Equal(t, details.StateRequested, coord.state.UpgradeDetails.Metadata.FailedState)
	require.Equal(t, expectedErr.Error(), coord.state.UpgradeDetails.Metadata.ErrorMsg)
}

func BenchmarkCoordinator_generateComponentModel(b *testing.B) {
	// load variables
	varsMaps := []map[string]any{}
	varsMapsBytes, err := os.ReadFile("./testdata/variables.yaml")
	require.NoError(b, err)
	err = yaml.Unmarshal(varsMapsBytes, &varsMaps)
	require.NoError(b, err)
	vars := make([]*transpiler.Vars, len(varsMaps))
	for i, vm := range varsMaps {
		vars[i], err = transpiler.NewVars(fmt.Sprintf("%d", i), vm, mapstr.M{}, "")
		require.NoError(b, err)
	}

	// load config
	cfgMap := map[string]any{}
	cfgMapBytes, err := os.ReadFile("./testdata/config.yaml")
	require.NoError(b, err)
	err = yaml.Unmarshal(cfgMapBytes, &cfgMap)
	require.NoError(b, err)
	cfg, err := config.NewConfigFrom(cfgMap)
	require.NoError(b, err)
	cfgMap, err = cfg.ToMapStr()
	require.NoError(b, err)
	cfgAst, err := transpiler.NewAST(cfgMap)
	require.NoError(b, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, _, _ := createCoordinator(b, ctx)

	coord.ast = cfgAst
	coord.vars = vars

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = coord.generateComponentModel()
		require.NoError(b, err)
	}

}

type createCoordinatorOpts struct {
	managed        bool
	upgradeManager UpgradeManager
	compInputSpec  component.InputSpec
	acker          acker.Acker
}

type CoordinatorOpt func(o *createCoordinatorOpts)

func ManagedCoordinator(managed bool) CoordinatorOpt {
	return func(o *createCoordinatorOpts) {
		o.managed = managed
	}
}

func WithUpgradeManager(upgradeManager UpgradeManager) CoordinatorOpt {
	return func(o *createCoordinatorOpts) {
		o.upgradeManager = upgradeManager
	}
}

func WithActionAcker(acker acker.Acker) CoordinatorOpt {
	return func(o *createCoordinatorOpts) {
		o.acker = acker
	}
}

func WithComponentInputSpec(spec component.InputSpec) CoordinatorOpt {
	return func(o *createCoordinatorOpts) {
		o.compInputSpec = spec
	}
}

// createCoordinator creates a coordinator that using a fake config manager and a fake vars manager.
//
// The runtime specifications is set up to use the fake component.
func createCoordinator(t testing.TB, ctx context.Context, opts ...CoordinatorOpt) (*Coordinator, *fakeConfigManager, *fakeVarsManager) {
	t.Helper()

	o := &createCoordinatorOpts{
		compInputSpec: fakeInputSpec,
	}
	for _, opt := range opts {
		opt(o)
	}

	l := newErrorLogger(t)

	ai, err := info.NewAgentInfo(ctx, false)
	require.NoError(t, err)

	componentSpec := component.InputRuntimeSpec{
		InputType:  "fake",
		BinaryName: "",
		BinaryPath: testBinary(t, "component"),
		Spec:       o.compInputSpec,
	}

	platform, err := component.LoadPlatformDetail()
	require.NoError(t, err)
	specs, err := component.NewRuntimeSpecs(platform, []component.InputRuntimeSpec{componentSpec})
	require.NoError(t, err)

	monitoringMgr := newTestMonitoringMgr()
	cfg := configuration.DefaultGRPCConfig()
	cfg.Port = 0
	rm, err := runtime.NewManager(l, l, ai, apmtest.DiscardTracer, monitoringMgr, cfg)
	require.NoError(t, err)
	otelMgr := &fakeOTelManager{}
	caps, err := capabilities.LoadFile(paths.AgentCapabilitiesPath(), l)
	require.NoError(t, err)

	cfgMgr := newFakeConfigManager()
	varsMgr := newFakeVarsManager()

	upgradeManager := o.upgradeManager
	if upgradeManager == nil {
		upgradeManager = &fakeUpgradeManager{}
	}

	acker := o.acker
	if acker == nil {
		acker = &fakeActionAcker{}
	}

	coord := New(l, nil, logp.DebugLevel, ai, specs, &fakeReExecManager{}, upgradeManager, rm, cfgMgr, varsMgr, caps, monitoringMgr, o.managed, otelMgr, acker)
	return coord, cfgMgr, varsMgr
}

func getComponentState(states []runtime.ComponentComponentState, componentID string) *runtime.ComponentComponentState {
	for _, state := range states {
		if state.Component.ID == componentID {
			return &state
		}
	}
	return nil
}

func newErrorLogger(t testing.TB) *logger.Logger {
	t.Helper()

	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.ErrorLevel

	eventLoggerCfg := logger.DefaultEventLoggingConfig()
	eventLoggerCfg.Level = loggerCfg.Level

	log, err := logger.NewFromConfig("", loggerCfg, eventLoggerCfg, false)
	require.NoError(t, err)
	return log
}

type fakeReExecManager struct {
}

func (f *fakeReExecManager) ReExec(callback reexec.ShutdownCallbackFn, _ ...string) {
	if callback != nil {
		_ = callback()
	}
}

var _ acker.Acker = &fakeActionAcker{}

type fakeActionAcker struct {
	mock.Mock
}

func (f *fakeActionAcker) Ack(ctx context.Context, action fleetapi.Action) error {
	args := f.Called(ctx, action)
	return args.Error(0)
}

func (f *fakeActionAcker) Commit(ctx context.Context) error {
	args := f.Called(ctx)
	return args.Error(0)
}

type fakeUpgradeManager struct {
	upgradeable   bool
	upgradeErr    error // An error to return when Upgrade is called
	upgradeCalled bool  // Set when Upgrade is called
}

func (f *fakeUpgradeManager) Upgradeable() bool {
	return f.upgradeable
}

func (f *fakeUpgradeManager) Reload(cfg *config.Config) error {
	return nil
}

func (f *fakeUpgradeManager) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, details *details.Details, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {
	f.upgradeCalled = true
	if f.upgradeErr != nil {
		return nil, f.upgradeErr
	}
	return func() error { return nil }, nil
}

func (f *fakeUpgradeManager) Ack(ctx context.Context, acker acker.Acker) error {
	if acker != nil {
		return acker.Ack(ctx, fleetapi.NewAction(fleetapi.ActionTypeUnknown))
	}
	return nil
}

func (f *fakeUpgradeManager) AckAction(ctx context.Context, acker acker.Acker, action fleetapi.Action) error {
	if acker != nil {
		return acker.Ack(ctx, action)
	}
	return nil
}

func (f *fakeUpgradeManager) MarkerWatcher() upgrade.MarkerWatcher {
	return nil
}

type testMonitoringManager struct{}

func newTestMonitoringMgr() *testMonitoringManager { return &testMonitoringManager{} }

func (*testMonitoringManager) EnrichArgs(_, _ string, args []string) []string { return args }
func (*testMonitoringManager) Prepare(string) error                           { return nil }
func (*testMonitoringManager) Cleanup(string) error                           { return nil }
func (*testMonitoringManager) Enabled() bool                                  { return false }
func (*testMonitoringManager) Reload(rawConfig *config.Config) error          { return nil }
func (*testMonitoringManager) MonitoringConfig(map[string]interface{}, []component.Component, map[string]uint64) (map[string]interface{}, error) {
	return nil, nil
}
func (*testMonitoringManager) ComponentMonitoringConfig(_, _ string) map[string]interface{} {
	return nil
}

type fakeConfigManager struct {
	errCh       chan error
	actionErrCh chan error
	cfgCh       chan ConfigChange
}

func newFakeConfigManager() *fakeConfigManager {
	return &fakeConfigManager{
		errCh:       make(chan error),
		actionErrCh: make(chan error),
		cfgCh:       make(chan ConfigChange),
	}
}

func (f *fakeConfigManager) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeConfigManager) Errors() <-chan error {
	return f.errCh
}

func (f *fakeConfigManager) ReportError(ctx context.Context, err error) {
	select {
	case <-ctx.Done():
	case f.errCh <- err:
	}
}

func (f *fakeConfigManager) ActionErrors() <-chan error {
	return f.actionErrCh
}

func (f *fakeConfigManager) ReportActionError(ctx context.Context, err error) {
	select {
	case <-ctx.Done():
	case f.actionErrCh <- err:
	}
}

func (f *fakeConfigManager) Watch() <-chan ConfigChange {
	return f.cfgCh
}

func (f *fakeConfigManager) Config(ctx context.Context, cfg *config.Config) {
	select {
	case <-ctx.Done():
	case f.cfgCh <- &configChange{cfg: cfg}:
	}
}

type configChange struct {
	cfg    *config.Config
	acked  bool  // Set if Ack() was called
	failed bool  // Set if Fail() was called
	err    error // Set to Fail's argument
}

func (l *configChange) Config() *config.Config {
	return l.cfg
}

func (l *configChange) Ack() error {
	l.acked = true
	return nil
}

func (l *configChange) Fail(err error) {
	l.failed = true
	l.err = err
}

type fakeVarsManager struct {
	varsMx sync.RWMutex
	vars   []*transpiler.Vars

	varsCh chan []*transpiler.Vars
	errCh  chan error

	observedMx sync.RWMutex
	observed   []string
}

func newFakeVarsManager() *fakeVarsManager {
	return &fakeVarsManager{
		varsCh: make(chan []*transpiler.Vars),
		errCh:  make(chan error),
	}
}

func (f *fakeVarsManager) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeVarsManager) Errors() <-chan error {
	return f.errCh
}

func (f *fakeVarsManager) ReportError(ctx context.Context, err error) {
	select {
	case <-ctx.Done():
	case f.errCh <- err:
	}
}

func (f *fakeVarsManager) Watch() <-chan []*transpiler.Vars {
	return f.varsCh
}

func (f *fakeVarsManager) Observe(ctx context.Context, observed []string) ([]*transpiler.Vars, error) {
	f.observedMx.Lock()
	defer f.observedMx.Unlock()
	f.observed = observed
	f.varsMx.RLock()
	defer f.varsMx.RUnlock()
	return f.vars, nil
}

func (f *fakeVarsManager) Vars(ctx context.Context, vars []*transpiler.Vars) {
	f.varsMx.Lock()
	f.vars = vars
	f.varsMx.Unlock()
	select {
	case <-ctx.Done():
	case f.varsCh <- vars:
	}
}

func (f *fakeVarsManager) DefaultProvider() string {
	return ""
}

var _ OTelManager = (*fakeOTelManager)(nil)

type fakeOTelManager struct {
	updateCollectorCallback             func(*confmap.Conf) error
	updateComponentCallback             func([]component.Component) error
	performDiagnosticsCallback          func(context.Context, ...runtime.ComponentUnitDiagnosticRequest) []runtime.ComponentUnitDiagnostic
	performComponentDiagnosticsCallback func(context.Context, []cproto.AdditionalDiagnosticRequest, ...component.Component) ([]runtime.ComponentDiagnostic, error)
	errChan                             chan error
	collectorStatusChan                 chan *status.AggregateStatus
	componentStateChan                  chan []runtime.ComponentComponentState
}

func (f *fakeOTelManager) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeOTelManager) Errors() <-chan error {
	return f.errChan
}

func (f *fakeOTelManager) Update(cfg *confmap.Conf, components []component.Component) {
	var collectorResult, componentResult error
	if f.updateCollectorCallback != nil {
		collectorResult = f.updateCollectorCallback(cfg)
	}
	if f.errChan != nil && collectorResult != nil {
		// If a reporting channel is set, send the collectorResult to it
		f.errChan <- collectorResult
	}
	if f.updateComponentCallback != nil {
		componentResult = f.updateComponentCallback(components)
	}
	if f.errChan != nil && componentResult != nil {
		// If a reporting channel is set, send the componentResult to it
		f.errChan <- componentResult
	}
}

func (f *fakeOTelManager) WatchCollector() <-chan *status.AggregateStatus {
	return f.collectorStatusChan
}

func (f *fakeOTelManager) WatchComponents() <-chan []runtime.ComponentComponentState {
	return f.componentStateChan
}

func (f *fakeOTelManager) MergedOtelConfig() *confmap.Conf { return nil }

func (f *fakeOTelManager) PerformDiagnostics(ctx context.Context, reqs ...runtime.ComponentUnitDiagnosticRequest) []runtime.ComponentUnitDiagnostic {
	if f.performDiagnosticsCallback != nil {
		return f.performDiagnosticsCallback(ctx, reqs...)
	}
	return nil
}

func (f *fakeOTelManager) PerformComponentDiagnostics(ctx context.Context, additionalMetrics []cproto.AdditionalDiagnosticRequest, req ...component.Component) ([]runtime.ComponentDiagnostic, error) {
	if f.performComponentDiagnosticsCallback != nil {
		return f.performComponentDiagnosticsCallback(ctx, additionalMetrics, req...)
	}
	return nil, nil
}

// An implementation of the RuntimeManager interface for use in testing.
type fakeRuntimeManager struct {
	state                               []runtime.ComponentComponentState
	updateCallback                      func([]component.Component) error
	performDiagnosticsCallback          func(context.Context, ...runtime.ComponentUnitDiagnosticRequest) []runtime.ComponentUnitDiagnostic
	performComponentDiagnosticsCallback func(context.Context, []cproto.AdditionalDiagnosticRequest, ...component.Component) ([]runtime.ComponentDiagnostic, error)
	result                              error
	errChan                             chan error
}

func (r *fakeRuntimeManager) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (r *fakeRuntimeManager) Errors() <-chan error { return nil }

func (r *fakeRuntimeManager) Update(model component.Model) {
	r.result = nil
	if r.updateCallback != nil {
		r.result = r.updateCallback(model.Components)
	}
	if r.errChan != nil {
		// If a reporting channel is set, send the result to it
		r.errChan <- r.result
	}
}

// State returns the current components model state.
func (r *fakeRuntimeManager) State() []runtime.ComponentComponentState {
	return r.state
}

// PerformAction executes an action on a unit.
func (r *fakeRuntimeManager) PerformAction(_ context.Context, _ component.Component, _ component.Unit, _ string, _ map[string]interface{}) (map[string]interface{}, error) {
	return nil, nil
}

// SubscribeAll provides an interface to watch for changes in all components.
func (r *fakeRuntimeManager) SubscribeAll(context.Context) *runtime.SubscriptionAll {
	return nil
}

// PerformDiagnostics executes the diagnostic action for the provided units. If no units are provided then
// it performs diagnostics for all current units.
func (r *fakeRuntimeManager) PerformDiagnostics(ctx context.Context, req ...runtime.ComponentUnitDiagnosticRequest) []runtime.ComponentUnitDiagnostic {
	if r.performDiagnosticsCallback != nil {
		return r.performDiagnosticsCallback(ctx, req...)
	}
	return nil
}

// PerformComponentDiagnostics  executes the diagnostic action for the provided components.
func (r *fakeRuntimeManager) PerformComponentDiagnostics(ctx context.Context, additionalMetrics []cproto.AdditionalDiagnosticRequest, req ...component.Component) ([]runtime.ComponentDiagnostic, error) {
	if r.performComponentDiagnosticsCallback != nil {
		return r.performComponentDiagnosticsCallback(ctx, additionalMetrics, req...)
	}
	return nil, nil
}

func testBinary(t testing.TB, name string) string {
	t.Helper()

	var err error
	binaryPath := filepath.Join("..", "..", "..", "..", "..", "pkg", "component", "fake", name, name)
	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		t.Fatalf("failed abs %s: %s", binaryPath, err)
	}
	if goruntime.GOOS == component.Windows {
		binaryPath += exeExt
	} else {
		err = os.Chown(binaryPath, os.Geteuid(), os.Getgid())
		if err != nil {
			t.Fatalf("failed chown %s: %s", binaryPath, err)
		}
		err = os.Chmod(binaryPath, 0755)
		if err != nil {
			t.Fatalf("failed chmod %s: %s", binaryPath, err)
		}
	}
	return binaryPath
}
