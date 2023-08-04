// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"

	"github.com/stretchr/testify/require"
	"go.elastic.co/apm/apmtest"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	exeExt = ".exe"
)

var (
	fakeInputSpec = component.InputSpec{
		Name:      "fake",
		Platforms: []string{fmt.Sprintf("%s/%s", goruntime.GOOS, goruntime.GOARCH)},
		Shippers:  []string{"fake-shipper"},
		Command: &component.CommandSpec{
			Timeouts: component.CommandTimeoutSpec{
				Checkin: 30 * time.Second,
				Restart: 10 * time.Millisecond, // quick restart during tests
				Stop:    30 * time.Second,
			},
		},
	}
	fakeShipperSpec = component.ShipperSpec{
		Name:      "fake-shipper",
		Platforms: []string{fmt.Sprintf("%s/%s", goruntime.GOOS, goruntime.GOARCH)},
		Outputs:   []string{"fake-action-output"},
		Command: &component.CommandSpec{
			Timeouts: component.CommandTimeoutSpec{
				Checkin: 30 * time.Second,
				Restart: 10 * time.Millisecond, // quick restart during tests
				Stop:    30 * time.Second,
			},
		},
	}
)

func TestCoordinator_State_Starting(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t)
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Starting && state.Message == "Waiting for initial configuration and composable variables"
	}, 3*time.Second, 10*time.Millisecond)

	// set vars state should stay same (until config)
	varsMgr.Vars(ctx, []*transpiler.Vars{{}})

	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Starting && state.Message == "Waiting for initial configuration and composable variables"
	}, 3*time.Second, 10*time.Millisecond)

	// set configuration should change to healthy
	cfg, err := config.NewConfigFrom(nil)
	require.NoError(t, err)
	cfgMgr.Config(ctx, cfg)

	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Healthy && state.Message == "Running"
	}, 3*time.Second, 10*time.Millisecond)

	cancel()
	err = <-coordCh
	require.NoError(t, err)
}

func TestCoordinator_State_VarsError(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t)
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

	// set an error on vars manager
	varsMgr.ReportError(ctx, errors.New("force error"))
	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Failed && state.Message == "force error"
	}, 3*time.Second, 10*time.Millisecond)

	// clear error
	varsMgr.ReportError(ctx, nil)
	assert.Eventually(t, func() bool {
		state := coord.State()
		return state.State == agentclient.Healthy && state.Message == "Running"
	}, 3*time.Second, 10*time.Millisecond)

	cancel()
	err = <-coordCh
	require.NoError(t, err)
}

func TestCoordinator_State_ConfigError_NotManaged(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t)
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
		return state.State == agentclient.Failed && state.Message == "force error"
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

func TestCoordinator_State_ConfigError_Managed(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t, ManagedCoordinator(true))
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

	cancel()
	err = <-coordCh
	require.NoError(t, err)
}

func TestCoordinator_StateSubscribe(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t)
	go func() {
		err := coord.Run(ctx)
		if errors.Is(err, context.Canceled) {
			// allowed error
			err = nil
		}
		coordCh <- err
	}()

	subCh := make(chan error)
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		sub := coord.StateSubscribe(ctx)
		for {
			select {
			case <-ctx.Done():
				subCh <- ctx.Err()
				return
			case state := <-sub.Ch():
				t.Logf("%+v", state)
				if len(state.Components) == 2 {
					compState := getComponentState(state.Components, "fake-default")
					if compState != nil {
						unit, ok := compState.State.Units[runtime.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-fake"}]
						if ok {
							if unit.State == client.UnitStateHealthy && unit.Message == "Healthy From Fake Config" {
								subCh <- nil
								return
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
				"type": "fake-action-output",
				"shipper": map[string]interface{}{
					"enabled": true,
				},
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

	err = <-subCh
	require.NoError(t, err)
	cancel()

	err = <-coordCh
	require.NoError(t, err)
}

func TestCoordinatorShutdownTimeout(t *testing.T) {
	CoordinatorShutdownTimeout = time.Millisecond
	handlerChan, _, _, _ := setupAndWaitCoordinatorDone()
	waitAndTestError(t, func(err error) bool { return errors.Is(err, context.Canceled) }, handlerChan)
}

func TestCoordinatorShutdownErrorOneResponse(t *testing.T) {
	CoordinatorShutdownTimeout = time.Millisecond
	handlerChan, _, _, config := setupAndWaitCoordinatorDone()

	cfgErrStr := "config watcher error"
	config <- errors.New(cfgErrStr)

	waitAndTestError(t, func(err error) bool { return strings.Contains(err.Error(), cfgErrStr) }, handlerChan)
}

func TestCoordinatorShutdownErrorAllResponses(t *testing.T) {
	CoordinatorShutdownTimeout = time.Millisecond
	handlerChan, runtime, varWatcher, config := setupAndWaitCoordinatorDone()
	runtimeErrStr := "runtime error"
	varsErrStr := "vars error"
	runtime <- errors.New(runtimeErrStr)
	varWatcher <- errors.New(varsErrStr)
	config <- nil

	waitAndTestError(t, func(err error) bool {
		return strings.Contains(err.Error(), runtimeErrStr) &&
			strings.Contains(err.Error(), varsErrStr)
	}, handlerChan)
}

func TestCoordinatorShutdownAllResponsesNoErrors(t *testing.T) {
	CoordinatorShutdownTimeout = time.Millisecond
	handlerChan, runtime, varWatcher, config := setupAndWaitCoordinatorDone()
	runtime <- nil
	varWatcher <- nil
	config <- nil

	waitAndTestError(t, func(err error) bool {
		return errors.Is(err, context.Canceled)
	}, handlerChan)
}

func waitAndTestError(t *testing.T, check func(error) bool, handlerErr chan error) {
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second*4)
	defer waitCancel()
	for {
		select {
		case <-waitCtx.Done():
			t.Fatalf("handleCoordinatorDone timed out while waiting for shutdown")
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

func setupAndWaitCoordinatorDone() (chan error, chan error, chan error, chan error) {
	runtime := make(chan error)
	varWatcher := make(chan error)
	config := make(chan error)

	testCord := Coordinator{logger: logp.L()}

	ctx, cancel := context.WithCancel(context.Background())
	// emulate shutdown
	cancel()

	handlerChan := make(chan error)
	go func() {
		handlerErr := testCord.handleCoordinatorDone(ctx, varWatcher, runtime, config)
		handlerChan <- handlerErr
	}()

	return handlerChan, runtime, varWatcher, config
}

func TestCoordinator_ReExec(t *testing.T) {
	coordCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, cfgMgr, varsMgr := createCoordinator(t)
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

	coord, cfgMgr, varsMgr := createCoordinator(t)
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

type createCoordinatorOpts struct {
	managed bool
}

type CoordinatorOpt func(o *createCoordinatorOpts)

func ManagedCoordinator(managed bool) CoordinatorOpt {
	return func(o *createCoordinatorOpts) {
		o.managed = managed
	}
}

// createCoordinator creates a coordinator that using a fake config manager and a fake vars manager.
//
// The runtime specifications is set up to use both the fake component and fake shipper.
func createCoordinator(t *testing.T, opts ...CoordinatorOpt) (*Coordinator, *fakeConfigManager, *fakeVarsManager) {
	t.Helper()

	o := &createCoordinatorOpts{}
	for _, opt := range opts {
		opt(o)
	}

	l := newErrorLogger(t)

	ai, err := info.NewAgentInfo(false)
	require.NoError(t, err)

	componentSpec := component.InputRuntimeSpec{
		InputType:  "fake",
		BinaryName: "",
		BinaryPath: testBinary(t, "component"),
		Spec:       fakeInputSpec,
	}
	shipperSpec := component.ShipperRuntimeSpec{
		ShipperType: "fake-shipper",
		BinaryName:  "",
		BinaryPath:  testBinary(t, "shipper"),
		Spec:        fakeShipperSpec,
	}

	platform, err := component.LoadPlatformDetail()
	require.NoError(t, err)
	specs, err := component.NewRuntimeSpecs(platform, []component.InputRuntimeSpec{componentSpec}, []component.ShipperRuntimeSpec{shipperSpec})
	require.NoError(t, err)

	monitoringMgr := newTestMonitoringMgr()
	rm, err := runtime.NewManager(l, l, "localhost:0", ai, apmtest.DiscardTracer, monitoringMgr, configuration.DefaultGRPCConfig())
	require.NoError(t, err)

	caps, err := capabilities.Load(paths.AgentCapabilitiesPath(), l)
	require.NoError(t, err)

	cfgMgr := newFakeConfigManager()
	varsMgr := newFakeVarsManager()

	coord := New(l, nil, logp.DebugLevel, ai, specs, &fakeReExecManager{}, &fakeUpgradeManager{}, rm, cfgMgr, varsMgr, caps, monitoringMgr, o.managed)
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

func newErrorLogger(t *testing.T) *logger.Logger {
	t.Helper()

	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.ErrorLevel

	log, err := logger.NewFromConfig("", loggerCfg, false)
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

type fakeUpgradeManager struct {
}

func (f *fakeUpgradeManager) Upgradeable() bool {
	return false
}

func (f *fakeUpgradeManager) Reload(_ *config.Config) error {
	return nil
}

<<<<<<< HEAD
func (f *fakeUpgradeManager) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, skipVerifyOverride bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {
=======
func (f *fakeUpgradeManager) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {
	f.upgradeCalled = true
	if f.upgradeErr != nil {
		return nil, f.upgradeErr
	}
>>>>>>> 2c9e581944 ([Integration Test] Upgrade failed default verification test (#3101))
	return func() error { return nil }, nil
}

func (f *fakeUpgradeManager) Ack(ctx context.Context, acker acker.Acker) error {
	return nil
}

type testMonitoringManager struct{}

func newTestMonitoringMgr() *testMonitoringManager { return &testMonitoringManager{} }

func (*testMonitoringManager) EnrichArgs(_ string, _ string, args []string) []string { return args }
func (*testMonitoringManager) Prepare(_ string) error                                { return nil }
func (*testMonitoringManager) Cleanup(string) error                                  { return nil }
func (*testMonitoringManager) Enabled() bool                                         { return false }
func (*testMonitoringManager) Reload(rawConfig *config.Config) error                 { return nil }
func (*testMonitoringManager) MonitoringConfig(_ map[string]interface{}, _ []component.Component, _ map[string]string) (map[string]interface{}, error) {
	return nil, nil
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
	case f.cfgCh <- &configChange{cfg}:
	}
}

type configChange struct {
	cfg *config.Config
}

func (l *configChange) Config() *config.Config {
	return l.cfg
}

func (l *configChange) Ack() error {
	// do nothing
	return nil
}

func (l *configChange) Fail(_ error) {
	// do nothing
}

type fakeVarsManager struct {
	varsCh chan []*transpiler.Vars
	errCh  chan error
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

func (f *fakeVarsManager) Vars(ctx context.Context, vars []*transpiler.Vars) {
	select {
	case <-ctx.Done():
	case f.varsCh <- vars:
	}
}

func testBinary(t *testing.T, name string) string {
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
