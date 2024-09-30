// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	gproto "google.golang.org/protobuf/proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.elastic.co/apm/v2/apmtest"

	fakecmp "github.com/elastic/elastic-agent/pkg/component/fake/component/comp"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/features"
)

const (
	exeExt             = ".exe"
	errActionUndefined = "action undefined"
)

var (
	fakeInputSpec = component.InputSpec{
		Name: "fake",
		Command: &component.CommandSpec{
			Timeouts: component.CommandTimeoutSpec{
				Checkin: 30 * time.Second,
				Restart: 10 * time.Millisecond, // quick restart during tests
				Stop:    30 * time.Second,
			},
		},
	}
)

type FakeInputSuite struct {
	suite.Suite
}

func (suite *FakeInputSuite) SetupSuite() {
	// Tests using the fake input need to override the
	// versionedHome and topPath globals to reference the temporary
	// directory the test is running in.
	// That's why these tests run in their own suite: it's hard to properly
	// clean up these global changes after a test without setting off the
	// data race detector, so they all run together and reset at the start of
	// each test.
	suite.setupTestPaths()
}

func TestFakeInputSuite(t *testing.T) {
	suite.Run(t, new(FakeInputSuite))
}

func (suite *FakeInputSuite) setupTestPaths() {
	t := suite.T()
	t.Helper()

	tmpDir := t.TempDir()
	paths.SetTop(tmpDir)
	paths.SetVersionHome(false)
}

func (suite *FakeInputSuite) TestManager_Features() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentInfo := &info.AgentInfo{}
	m, err := NewManager(
		newDebugLogger(t),
		newDebugLogger(t),
		agentInfo,
		apmtest.DiscardTracer,
		newTestMonitoringMgr(),
		testGrpcConfig(),
		false)
	require.NoError(t, err)

	managerErrCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		managerErrCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := waitForReady(waitCtx, m); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	const compID = "fake-default"
	comp := component.Component{
		ID: compID,
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subscriptionCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subscriptionErrCh := make(chan error)
	doneCh := make(chan struct{})

	go func() {
		sub := m.Subscribe(subscriptionCtx, compID)
		var healthIteration int

		for {
			select {
			case <-subscriptionCtx.Done():
				return
			case componentState := <-sub.Ch():
				t.Logf("component state changed: %+v", componentState)

				if componentState.State == client.UnitStateFailed {
					subscriptionErrCh <- fmt.Errorf("component failed: %s", componentState.Message)
					return
				}

				unit, ok := componentState.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
				if !ok {
					subscriptionErrCh <- errors.New("unit missing: fake-input")
					return
				}

				switch unit.State {
				case client.UnitStateFailed:
					subscriptionErrCh <- fmt.Errorf("unit failed: %s", unit.Message)

				case client.UnitStateHealthy:
					healthIteration++
					switch healthIteration {
					case 1: // yes, it's starting on 1
						comp.Features = &proto.Features{
							Fqdn: &proto.FQDNFeature{Enabled: true},
						}

						m.Update(component.Model{Components: []component.Component{comp}})
						err := <-m.errCh
						if err != nil {
							subscriptionErrCh <- fmt.Errorf("[case %d]: failed to update component: %w",
								healthIteration, err)
							return
						}

					// check if config sent on iteration 1 was set
					case 2:
						// In the previous iteration, the (fake) component has received a CheckinExpected
						// message to enable the feature flag for FQDN.  In this iteration we are about to
						// retrieve the feature flags information from the same component via the retrieve_features
						// action. Within the component, which is running as a separate process, actions
						// and CheckinExpected messages are processed concurrently.  We need some way to wait
						// a reasonably short amount of time for the CheckinExpected message to be applied by the
						// component (thus setting the FQDN feature flag to true) before we as the same component
						// for feature flags information.  We accomplish this via assert.Eventually.
						assert.Eventuallyf(t, func() bool {
							// check the component
							res, err := m.PerformAction(
								context.Background(),
								comp,
								comp.Units[0],
								fakecmp.ActionRetrieveFeatures,
								nil)
							if err != nil {
								subscriptionErrCh <- fmt.Errorf("[case %d]: failed to PerformAction %s: %w",
									healthIteration, fakecmp.ActionRetrieveFeatures, err)
								return false
							}

							ff, err := features.Parse(map[string]any{"agent": res})
							if err != nil {
								subscriptionErrCh <- fmt.Errorf("[case %d]: failed to parse action %s response as features config: %w",
									healthIteration, fakecmp.ActionRetrieveFeatures, err)
								return false
							}

							return ff.FQDN()
						}, 1*time.Second, 100*time.Millisecond, "failed to assert that FQDN feature flag was enabled by component")

						doneCh <- struct{}{}
					}

				case client.UnitStateStarting:
					// acceptable

				case client.UnitStateConfiguring:
					// set unit back to healthy, so other cases will run.
					comp.Units[0].Config = component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy",
					})

					m.Update(component.Model{Components: []component.Component{comp}})
					err := <-m.errCh
					if err != nil {
						t.Logf("error updating component state to health: %v", err)

						subscriptionErrCh <- fmt.Errorf("failed to update component: %w", err)
					}

				default:
					// unexpected state that should not have occurred
					subscriptionErrCh <- fmt.Errorf("unit reported unexpected state: %v",
						unit.State)
				}

			}
		}
	}()

	defer drainErrChan(managerErrCh)
	defer drainErrChan(subscriptionErrCh)

	m.Update(component.Model{Components: []component.Component{comp}})
	err = <-m.errCh
	require.NoError(t, err)

	timeout := 30 * time.Second
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	// Wait for a success, an error or time out
	for {
		select {
		case <-timeoutTimer.C:
			t.Fatalf("timed out after %s", timeout)
		case err := <-managerErrCh:
			require.NoError(t, err)
		case err := <-subscriptionErrCh:
			require.NoError(t, err)
		case <-doneCh:
			subCancel()
			cancel()

			err = <-managerErrCh
			require.NoError(t, err)
			return
		}
	}
}

func (suite *FakeInputSuite) TestManager_APM() {
	t := suite.T()

	timeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	agentInfo := &info.AgentInfo{}
	m, err := NewManager(
		newDebugLogger(t),
		newDebugLogger(t),
		agentInfo,
		apmtest.DiscardTracer,
		newTestMonitoringMgr(),
		testGrpcConfig(),
		false)
	require.NoError(t, err)

	managerErrCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		managerErrCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := waitForReady(waitCtx, m); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	const compID = "fake-default"
	comp := component.Component{
		ID: compID,
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subscriptionCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()

	FiftyPercentSamplingRate := float32(0.5)
	OnePercentSamplingRate := float32(0.01)

	initialAPMConfig := &proto.APMConfig{
		Elastic: &proto.ElasticAPM{
			Environment: "test",
			ApiKey:      "apiKey",
			SecretToken: "secretToken",
			Hosts:       []string{"host1", "host2", "host3"},
			Tls: &proto.ElasticAPMTLS{
				SkipVerify: true,
				ServerCert: "servercert",
				ServerCa:   "serverca",
			},
			SamplingRate: &FiftyPercentSamplingRate,
		},
	}

	modifiedAPMConfig := &proto.APMConfig{
		Elastic: &proto.ElasticAPM{
			Environment: "test-modified",
			ApiKey:      "apiKey",
			SecretToken: "secretToken",
			Hosts:       []string{"newhost1", "host2", "differenthost3"},
			Tls: &proto.ElasticAPMTLS{
				SkipVerify: true,
				ServerCert: "",
				ServerCa:   "",
			},
			SamplingRate: &OnePercentSamplingRate,
		},
	}

	modifiedSampleRateAPMConfig := &proto.APMConfig{
		Elastic: &proto.ElasticAPM{
			Environment: "test-modified",
			ApiKey:      "apiKey",
			SecretToken: "secretToken",
			Hosts:       []string{"newhost1", "host2", "differenthost3"},
			Tls: &proto.ElasticAPMTLS{
				SkipVerify: true,
				ServerCert: "",
				ServerCa:   "",
			},
			SamplingRate: &FiftyPercentSamplingRate,
		},
	}

	sub := m.Subscribe(subscriptionCtx, compID)

	m.Update(component.Model{Components: []component.Component{comp}})
	err = <-m.errCh
	require.NoError(t, err, "manager Update call must succeed")

	// testStep tracks how far into the test sequence we've progressed.
	// 0: When unit is healthy, set initialAPMConfig
	// 1: When initialAPMConfig is active, set modifiedAPMConfig
	// 2: When modifiedAPMConfig is active, set modifiedSampleRateAPMConfig
	// 3: When modifiedSampleRateAPMConfig is active, clear all APMConfig
	// 4: When APM config is empty again, succeed
	var testStep int
STATELOOP:
	for {
		select {
		case <-ctx.Done():
			require.Fail(t, "timed out waiting for state update")
		case componentState := <-sub.Ch():
			t.Logf("component state changed: %+v", componentState)

			require.NotEqual(t, client.UnitStateFailed, componentState.State, "component failed: %v", componentState.Message)

			unit, ok := componentState.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
			require.True(t, ok, "input unit missing: fake-input")

			if unit.State == client.UnitStateStarting || unit.State == client.UnitStateConfiguring {
				// Unit is still starting or reconfiguring, skip to next update
				continue STATELOOP
			}

			require.Equal(t, client.UnitStateHealthy, unit.State, "unit isn't healthy: %v", unit.Message)

			t.Logf("Healthy iteration %d starting at %s", testStep, time.Now())
			switch testStep {
			case 0:
				// Add an APM config to the component config and send an update.
				comp.Component = &proto.Component{
					ApmConfig: initialAPMConfig,
				}
				m.Update(component.Model{Components: []component.Component{comp}})
				err = <-m.errCh
				require.NoError(t, err, "manager Update call must succeed")

			case 1:
				// First, check that the APM config set in the previous step is
				// visible, if not then we need to wait for a future update
				if componentState.Component == nil {
					continue STATELOOP
				}

				// The APM config has propagated to the component state, now make sure
				// it's visible when retrieving via action.
				// We use require.Eventually because the new value isn't guaranteed
				// to immediately propagate via Action even after it appears in the
				// component checkin.

				require.Eventually(t,
					func() bool {
						retrievedAPMConfig := fetchAPMConfigWithAction(t, ctx, m, comp)
						return gproto.Equal(initialAPMConfig, retrievedAPMConfig)
					},
					3*time.Second,
					50*time.Millisecond,
					"Updated APM config should be reported by Actions")

				// Config matches, we now try updating to a new APM config
				comp.Component = &proto.Component{
					ApmConfig: modifiedAPMConfig,
				}
				m.Update(component.Model{Components: []component.Component{comp}})
				err = <-m.errCh
				require.NoError(t, err, "manager Update call must succeed")

			case 2:
				require.NotNil(t, componentState.Component, "ApmConfig must not be nil")

				require.Eventually(t,
					func() bool {
						retrievedAPMConfig := fetchAPMConfigWithAction(t, ctx, m, comp)
						return gproto.Equal(modifiedAPMConfig, retrievedAPMConfig)
					},
					3*time.Second,
					50*time.Millisecond,
					"Updated APM config should be reported by Actions")

				// Config matches, we now try setting a modified sample rate config
				comp.Component = &proto.Component{
					ApmConfig: modifiedSampleRateAPMConfig,
				}

				m.Update(component.Model{Components: []component.Component{comp}})
				err = <-m.errCh
				require.NoError(t, err, "manager Update call must succeed")

			case 3:
				require.NotNil(t, componentState.Component, "ApmConfig must not be nil")

				require.Eventually(t,
					func() bool {
						retrievedAPMConfig := fetchAPMConfigWithAction(t, ctx, m, comp)
						return gproto.Equal(modifiedSampleRateAPMConfig, retrievedAPMConfig)
					},
					3*time.Second,
					50*time.Millisecond,
					"Updated sample rate APM config should be reported by Actions")

				// All configs were reported correctly, now clear the APM config
				comp.Component = &proto.Component{
					ApmConfig: nil,
				}

				m.Update(component.Model{Components: []component.Component{comp}})
				err = <-m.errCh
				require.NoError(t, err, "manager Update call must succeed")

			case 4:
				if componentState.Component != nil && componentState.Component.ApmConfig != nil {
					// APM config is still present, wait for next update
					continue STATELOOP
				}

				require.Eventually(t,
					func() bool {
						retrievedAPMConfig := fetchAPMConfigWithAction(t, ctx, m, comp)
						return retrievedAPMConfig == nil
					},
					3*time.Second,
					50*time.Millisecond,
					"Final APM config should be nil")

				// Success, end the loop
				break STATELOOP
			}
			testStep++
		}
	}

	subCancel()
	cancel()

	err = <-managerErrCh
	require.NoError(t, err)
}

func fetchAPMConfigWithAction(t *testing.T, ctx context.Context, m *Manager, comp component.Component) *proto.APMConfig {
	res, err := m.PerformAction(
		context.Background(),
		comp,
		comp.Units[0],
		fakecmp.ActionRetrieveAPMConfig,
		nil)
	require.NoError(t, err, "failed to retrieve APM config")

	apmCfg, ok := res["apm"]
	require.True(t, ok, "ActionResult must contain top-level 'apm' key")
	if apmCfg == nil {
		// the APM config is not set on the component
		return nil
	}

	jsonApmConfig, ok := apmCfg.(string)
	require.True(t, ok, "'apm' key must contain a string")

	retrievedApmConfig := new(proto.APMConfig)
	err = protojson.Unmarshal([]byte(jsonApmConfig), retrievedApmConfig)
	require.NoError(t, err, "'apm' key must contain valid json", jsonApmConfig)
	return retrievedApmConfig
}

func (suite *FakeInputSuite) TestManager_Limits() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentInfo := &info.AgentInfo{}
	m, err := NewManager(
		newDebugLogger(t),
		newDebugLogger(t),
		agentInfo,
		apmtest.DiscardTracer,
		newTestMonitoringMgr(),
		testGrpcConfig(),
		false,
	)
	require.NoError(t, err)

	managerErrCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		managerErrCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := waitForReady(waitCtx, m); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	const compID = "fake-default"
	var compMu sync.Mutex
	comp := component.Component{
		ID: compID,
		Component: &proto.Component{
			Limits: &proto.ComponentLimits{
				GoMaxProcs: 99,
			},
		},
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{},
	}

	subscriptionCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subscriptionErrCh := make(chan error)
	doneCh := make(chan struct{})

	go func() {
		sub := m.Subscribe(subscriptionCtx, compID)
		var healthyIteration int

		for {
			select {
			case <-subscriptionCtx.Done():
				return

			case componentState := <-sub.Ch():

				t.Logf("component state changed: %+v", componentState)

				switch componentState.State {
				case client.UnitStateHealthy:
					compMu.Lock()
					comp := comp // local copy for changes
					compMu.Unlock()
					healthyIteration++

					switch healthyIteration {
					// check that the initial value was set correctly
					case 1:
						assert.NotNil(t, componentState.Component)
						assert.NotNil(t, componentState.Component.Limits)
						assert.Equal(t, uint64(99), componentState.Component.Limits.GoMaxProcs)

						// then make a change and see how it's reflected on the next healthy state
						// we must replace the whole section to keep it thread-safe
						comp.Component = &proto.Component{
							Limits: &proto.ComponentLimits{
								GoMaxProcs: 101,
							},
						}
						m.Update(component.Model{
							Components: []component.Component{comp},
						})
						err := <-m.errCh
						if err != nil {
							subscriptionErrCh <- fmt.Errorf("[case %d]: failed to update component: %w",
								healthyIteration, err)
							return
						}
					// check if the change was handled
					case 2:
						assert.NotNil(t, componentState.Component)
						assert.NotNil(t, componentState.Component.Limits)
						assert.Equal(t, uint64(101), componentState.Component.Limits.GoMaxProcs)

						comp.Component = nil
						m.Update(component.Model{
							Components: []component.Component{comp},
						})
						err := <-m.errCh
						if err != nil {
							subscriptionErrCh <- fmt.Errorf("[case %d]: failed to update component: %w",
								healthyIteration, err)
							return
						}
					// check if the empty config is handled
					case 3:
						assert.Nil(t, componentState.Component)
						doneCh <- struct{}{}
					}
				// allowed states
				case client.UnitStateStarting:
				case client.UnitStateConfiguring:
				default:
					// unexpected state that should not have occurred
					subscriptionErrCh <- fmt.Errorf("unit reported unexpected state: %v",
						componentState.State)
				}
			}
		}
	}()

	defer drainErrChan(managerErrCh)
	defer drainErrChan(subscriptionErrCh)

	m.Update(component.Model{Components: []component.Component{comp}})
	err = <-m.errCh
	require.NoError(t, err)

	timeout := 30 * time.Second
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	// Wait for a success, an error or time out
	for {
		select {
		case <-timeoutTimer.C:
			t.Fatalf("timed out after %s", timeout)
		case err := <-managerErrCh:
			require.NoError(t, err)
		case err := <-subscriptionErrCh:
			require.NoError(t, err)
		case <-doneCh:
			subCancel()
			cancel()

			err = <-managerErrCh
			require.NoError(t, err)
			return
		}
	}
}

func (suite *FakeInputSuite) TestManager_BadUnitToGood() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
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

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
			{
				ID:   "bad-input",
				Type: client.UnitTypeInput,
				Err:  errors.New("hard-error for config"),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		unitBad := true

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							// update the bad unit to be good; so it will transition to healthy
							updatedComp := comp
							updatedComp.Units = make([]component.Unit, len(comp.Units))
							copy(updatedComp.Units, comp.Units)
							updatedComp.Units[1] = component.Unit{
								ID:       "bad-input",
								Type:     client.UnitTypeInput,
								LogLevel: client.UnitLogLevelTrace,
								Config: component.MustExpectedConfig(map[string]interface{}{
									"type":    "fake",
									"state":   int(client.UnitStateHealthy),
									"message": "Fake Healthy 2",
								}),
							}

							unitBad = false
							m.Update(component.Model{Components: []component.Component{updatedComp}})
							err := <-m.errCh
							if err != nil {
								subErrCh <- err
							}
						} else if unit.State == client.UnitStateStopped || unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
					unit, ok = state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "bad-input"}]
					if ok {
						if unitBad {
							if unit.State != client.UnitStateFailed {
								subErrCh <- errors.New("bad-input unit should be failed")
							}
						} else {
							if unit.State == client.UnitStateFailed {
								if unit.Message == "hard-error for config" {
									// still hard-error; wait for it to go healthy
								} else {
									subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
								}
							} else if unit.State == client.UnitStateHealthy {
								// bad unit is now healthy; stop the component
								m.Update(component.Model{Components: []component.Component{}})
								err := <-m.errCh
								if err != nil {
									subErrCh <- err
								}
							} else if unit.State == client.UnitStateStopped {
								subErrCh <- nil
							} else if unit.State == client.UnitStateStarting {
								// acceptable
							} else {
								// unknown state that should not have occurred
								subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
							}
						}
					} else {
						subErrCh <- errors.New("unit missing: bad-input")
					}
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

func (suite *FakeInputSuite) TestManager_GoodUnitToBad() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
	require.NoError(t, err)
	runResultChan := make(chan error, 1)
	go func() {
		runResultChan <- m.Run(ctx)
	}()

	binaryPath := testBinary(t, "component")
	healthyComp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
			{
				ID:       "good-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Health 2",
				}),
			},
		},
	}
	// unhealthyComp is a copy of healthyComp with an error inserted in the
	// second unit
	unhealthyComp := healthyComp
	unhealthyComp.Units = make([]component.Unit, len(healthyComp.Units))
	copy(unhealthyComp.Units, healthyComp.Units)
	unhealthyComp.Units[1] = component.Unit{
		ID:   "good-input",
		Type: client.UnitTypeInput,
		Err:  errors.New("hard-error for config"),
	}
	goodUnitKey := ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "good-input"}

	// Wait for Manager to start up
	timedWaitForReady(t, m, 1*time.Second)

	sub := m.Subscribe(ctx, "fake-default")

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()

	m.Update(component.Model{Components: []component.Component{healthyComp}})
	err = <-m.errCh
	require.NoError(t, err)

	// nextState tracks the stage of the test. We expect the sequence
	// Starting -> Healthy -> Failed -> Stopped.
	nextState := client.UnitStateHealthy

LOOP:
	for {
		var state ComponentState
		select {
		case <-endTimer.C:
			require.Fail(t, "timed out waiting for component state update")
		case state = <-sub.Ch():
			t.Logf("component state changed: %+v", state)
		}

		require.NotEqual(t, client.UnitStateFailed, state.State, "component should not fail")
		unit, ok := state.Units[goodUnitKey]
		require.True(t, ok, "unit good-input must be present")

		if nextState == client.UnitStateHealthy {
			// Waiting for unit to become healthy, if it's still starting skip
			// to the next update
			if unit.State == client.UnitStateStarting {
				continue LOOP
			}
			if unit.State == client.UnitStateHealthy {
				// good unit is healthy; now make it bad
				t.Logf("marking good-input as having a hard-error for config")
				m.Update(component.Model{Components: []component.Component{unhealthyComp}})
				err := <-m.errCh
				require.NoError(t, err, "Component model update should succeed")

				// We next expect to transition to Failed
				nextState = client.UnitStateFailed
			} else {
				// Unit should only be starting or healthy in this stage,
				// anything else is an error.
				require.FailNowf(t, "Incorrect state", "Expected STARTING or HEALTHY, got %v", unit.State)
			}
		} else if nextState == client.UnitStateFailed {
			// Waiting for unit to fail, if it's still healthy skip to the next
			// update
			if unit.State == client.UnitStateHealthy {
				continue LOOP
			}
			if unit.State == client.UnitStateFailed {
				// Reached the expected state, now send an empty component model
				// to stop everything.
				m.Update(component.Model{Components: []component.Component{}})
				err := <-m.errCh
				require.NoError(t, err, "Component model update should succeed")
				nextState = client.UnitStateStopped
			} else {
				// Unit should only be healthy or failed in this stage, anything
				// else is an error.
				require.FailNow(t, "Incorrect state", "Expected HEALTHY or FAILED, got %v", unit.State)
			}
		} else if nextState == client.UnitStateStopped {
			// Waiting for component to stop, if it's still Failed skip to
			// the next update
			if unit.State == client.UnitStateFailed {
				continue LOOP
			}
			if unit.State == client.UnitStateStopped {
				// Success, we've finished the whole sequence
				break LOOP
			} else {
				// Unit should only be failed or stopped in this stage, anything
				// else is an error.
				require.FailNowf(t, "Incorrect state", "Expected FAILED or STOPPED, got %v", unit.State)
			}
		}
	}

	cancel()
	err = <-runResultChan
	require.Equal(t, context.Canceled, err, "Run should return with context canceled, got %v", err.Error())
}

// A component that can be fed to Manager.Update, with an index to allow
// looping with distinct configurations at each step.
func noDeadlockTestComponent(t *testing.T, index int) component.Component {
	binaryPath := testBinary(t, "component")
	return component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelError, // test log will get spammed with the constant updates (error to prevent spam)
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": fmt.Sprintf("Fake Healthy %d", index),
				}),
			},
		},
	}
}

func (suite *FakeInputSuite) TestManager_NoDeadlock() {
	t := suite.T()
	// NOTE: This is a long-running test that spams the runtime managers `Update` function to try and
	// trigger a deadlock. This test takes 2 minutes to run trying to re-produce issue:
	// https://github.com/elastic/elastic-agent/issues/2691

	// How long to run the test
	testDuration := 2 * time.Minute

	// How long without an update before we report it as a deadlock
	maxUpdateInterval := 15 * time.Second

	// Create the runtime manager
	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
	require.NoError(t, err)

	// Start the runtime manager in a goroutine, passing its termination state
	// to managerResultChan.
	managerCtx, managerCancel := context.WithCancel(context.Background())
	defer managerCancel()
	managerResultChan := make(chan error)
	go func() {
		managerResultChan <- m.Run(managerCtx)
	}()

	// Wait for the manager to become active
	timedWaitForReady(t, m, 1*time.Second)

	// Start a goroutine to spam the manager update trying to cause
	// a deadlock. When the test context finishes, the update loop
	// closes updateResultChan to signal that it is done.
	updateResultChan := make(chan error)
	updateLoopCtx, updateLoopCancel := context.WithTimeout(context.Background(), testDuration)
	defer updateLoopCancel()
	go func() {
		defer close(updateResultChan)
		for i := 0; updateLoopCtx.Err() == nil; i++ {
			comp := noDeadlockTestComponent(t, i)
			m.Update(component.Model{Components: []component.Component{comp}})
			err := <-m.errCh
			updateResultChan <- err
			if err != nil {
				// If the update gave an error, end the test
				return
			}
		}
	}()

	// The component state is being changed constantly. If updateTimeout
	// triggers without any updates, report it as a deadlock.
	updateTimeout := time.NewTicker(maxUpdateInterval)
	defer updateTimeout.Stop()
LOOP:
	for {
		select {
		case err, ok := <-updateResultChan:
			if ok {
				// update did occur
				require.NoError(t, err)
				updateTimeout.Reset(15 * time.Second)
			} else {
				// Update goroutine is terminating, test is over
				break LOOP
			}
		case <-managerResultChan:
			require.Fail(t, "Runtime manager terminated before test was over")
		case <-updateTimeout.C:
			require.Fail(t, "Timed out waiting for Manager.Update result")
		}
	}
	// Finished without a deadlock. Stop the component and shut down the manager.
	m.Update(component.Model{Components: []component.Component{}})
	err = <-m.errCh
	require.NoError(t, err)

	managerCancel()
	err = <-managerResultChan
	require.Equal(t, err, context.Canceled)
}

func (suite *FakeInputSuite) TestManager_Configure() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
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

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							// update config to change the state to degraded
							comp.Units[0].Config = component.MustExpectedConfig(map[string]interface{}{
								"type":    "fake",
								"state":   int(client.UnitStateDegraded),
								"message": "Fake Degraded",
							})
							m.Update(component.Model{Components: []component.Component{comp}})
							err := <-m.errCh
							if err != nil {
								subErrCh <- err
							}
						} else if unit.State == client.UnitStateDegraded {
							subErrCh <- nil
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
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

func (suite *FakeInputSuite) TestManager_RemoveUnit() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
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

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input-0",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy 0",
				}),
			},
			{
				ID:       "fake-input-1",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy 1",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		unit1Stopped := false

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit0, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input-0"}]
					if ok {
						if unit0.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit 0 failed: %s", unit0.Message)
						} else if unit0.State == client.UnitStateStarting || unit0.State == client.UnitStateHealthy {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit 0 reported unexpected state: %v", unit0.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input-0")
					}
					unit1, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input-1"}]
					if ok {
						if unit1.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit 1 failed: %s", unit1.Message)
						} else if unit1.State == client.UnitStateHealthy {
							// unit1 is healthy lets remove it from the component
							comp.Units = comp.Units[0:1]
							m.Update(component.Model{Components: []component.Component{comp}})
							err = <-m.errCh
							if err != nil {
								subErrCh <- err
							}
						} else if unit1.State == client.UnitStateStarting || unit1.State == client.UnitStateStopping {
							// acceptable
						} else if unit1.State == client.UnitStateStopped {
							// unit should have been reported stopped before being removed
							unit1Stopped = true
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit 1 reported unexpected state: %v", unit1.State)
						}
					} else {
						if len(comp.Units) == 1 {
							if unit1Stopped {
								// unit reported stopped then removed (perfect!)
								subErrCh <- nil
							} else {
								// never reported stopped
								subErrCh <- errors.New("unit 1 removed but not reported stop first")
							}
						} else {
							// should not be removed
							subErrCh <- errors.New("unit missing: fake-input-1")
						}
					}
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

func (suite *FakeInputSuite) TestManager_ActionState() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
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

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							// must be called in a separate go routine because it cannot block receiving from the
							// subscription channel
							go func() {
								actionCtx, actionCancel := context.WithTimeout(context.Background(), 15*time.Second)
								_, err := m.PerformAction(actionCtx, comp, comp.Units[0], "set_state", map[string]interface{}{
									"state":   int(client.UnitStateDegraded),
									"message": "Action Set Degraded",
								})
								actionCancel()
								if err != nil {
									subErrCh <- err
								}
							}()
						} else if unit.State == client.UnitStateDegraded {
							// action set it to degraded
							subErrCh <- nil
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
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

func (suite *FakeInputSuite) TestManager_Restarts() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
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

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		killed := false

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					if !killed {
						subErrCh <- fmt.Errorf("component failed: %s", state.Message)
					}
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							if !killed {
								subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
							}
						} else if unit.State == client.UnitStateHealthy {
							// force the input to exit and it should be restarted
							if !killed {
								killed = true

								t.Log("triggering kill through action")
								actionCtx, actionCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
								_, err := m.PerformAction(actionCtx, comp, comp.Units[0], "kill", nil)
								actionCancel()
								if !errors.Is(err, context.DeadlineExceeded) {
									// should have got deadline exceeded for this call
									if err == nil {
										err = fmt.Errorf("should have got deadline exceeded")
									} else {
										err = fmt.Errorf("should have got deadline exceeded, instead got: %w", err)
									}
									subErrCh <- err
								}
							} else {
								// got back to healthy after kill
								subErrCh <- nil
							}
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
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

func (suite *FakeInputSuite) TestManager_Restarts_ConfigKill() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
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

	// adjust input spec to allow restart
	cmdSpec := *fakeInputSpec.Command
	cmdSpec.RestartMonitoringPeriod = 1 * time.Second
	cmdSpec.MaxRestartsPerPeriod = 10
	inputSpec := fakeInputSpec
	inputSpec.Command = &cmdSpec

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       inputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		killed := false

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					if !killed {
						subErrCh <- fmt.Errorf("component failed: %s", state.Message)
					}
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							if !killed {
								subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
							}
						} else if unit.State == client.UnitStateHealthy {
							// force the input to exit and it should be restarted
							if !killed {
								killed = true

								r := regexp.MustCompile(`pid \'(?P<pid>\d+)\'`)
								rp := r.FindStringSubmatch(state.Message)
								t.Logf("triggering kill through config on pid %s", rp)
								comp.Units[0].Config = component.MustExpectedConfig(map[string]interface{}{
									"type":    "fake",
									"state":   int(client.UnitStateHealthy),
									"message": "Fake Healthy",
									"kill":    rp[1],
								})
								m.Update(component.Model{Components: []component.Component{comp}})
								err := <-m.errCh
								if err != nil {
									subErrCh <- err
								}
							} else {
								// got back to healthy after kill
								subErrCh <- nil
							}
						} else if unit.State == client.UnitStateStarting || unit.State == client.UnitStateStopped {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	m.Update(component.Model{Components: []component.Component{comp}})
	err = <-m.errCh
	require.NoError(t, err)

	endTimer := time.NewTimer(1 * time.Minute)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 1 minute")
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

func (suite *FakeInputSuite) TestManager_KeepsRestarting() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
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

	// adjust input spec to allow restart
	cmdSpec := *fakeInputSpec.Command
	cmdSpec.RestartMonitoringPeriod = 1 * time.Second
	cmdSpec.MaxRestartsPerPeriod = 10
	inputSpec := fakeInputSpec
	inputSpec.Command = &cmdSpec

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       inputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":             "fake",
					"state":            int(client.UnitStateHealthy),
					"message":          "Fake Healthy",
					"kill_on_interval": true,
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		lastStoppedCount := 0
		stoppedCount := 0

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					// should not go failed because we allow restart per period
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							// unit should not be failed because we allow restart per period
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							if lastStoppedCount != stoppedCount {
								lastStoppedCount = stoppedCount

								// send new config on each healthy report
								comp.Units[0].Config = component.MustExpectedConfig(map[string]interface{}{
									"type":             "fake",
									"state":            int(client.UnitStateHealthy),
									"message":          fmt.Sprintf("Fake Healthy %d", lastStoppedCount),
									"kill_on_interval": true,
								})
								m.Update(component.Model{Components: []component.Component{comp}})
								err := <-m.errCh
								if err != nil {
									subErrCh <- err
								}
							}
							if stoppedCount >= 3 {
								// got stopped 3 times and got back to healthy
								subErrCh <- nil
							}
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else if unit.State == client.UnitStateStopped {
							stoppedCount += 1
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	m.Update(component.Model{Components: []component.Component{comp}})
	err = <-m.errCh
	require.NoError(t, err)

	endTimer := time.NewTimer(1 * time.Minute)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 1 minute")
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

func (suite *FakeInputSuite) TestManager_RestartsOnMissedCheckins() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
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

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec: component.InputSpec{
				Name: "fake",
				Command: &component.CommandSpec{
					Timeouts: component.CommandTimeoutSpec{
						// very low checkin timeout so we can cause missed check-ins
						Checkin: 100 * time.Millisecond,
						Restart: 10 * time.Second,
						Stop:    30 * time.Second,
					},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "fake-input",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		wasDegraded := false

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)

				switch state.State {
				case client.UnitStateStarting:
				case client.UnitStateHealthy:
					// starting and healthy are allowed
				case client.UnitStateDegraded:
					// should go to degraded first
					wasDegraded = true
				case client.UnitStateFailed:
					if wasDegraded {
						subErrCh <- nil
					} else {
						subErrCh <- errors.New("should have been degraded before failed")
					}
				default:
					subErrCh <- fmt.Errorf("unknown component state: %v", state.State)
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

func (suite *FakeInputSuite) TestManager_InvalidAction() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), testGrpcConfig(),
		false)
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

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:   "fake-input",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							actionCtx, actionCancel := context.WithTimeout(context.Background(), 5*time.Second)
							_, err := m.PerformAction(actionCtx, comp, comp.Units[0], "invalid_missing_action", nil)
							actionCancel()
							if err == nil {
								subErrCh <- fmt.Errorf("should have returned an error")
							} else if err.Error() != errActionUndefined {
								subErrCh <- fmt.Errorf("should have returned error: action undefined")
							} else {
								subErrCh <- nil
							}
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
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

func (suite *FakeInputSuite) TestManager_MultiComponent() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentInfo := &info.AgentInfo{}
	m, err := NewManager(
		newDebugLogger(t),
		newDebugLogger(t),
		agentInfo,
		apmtest.DiscardTracer,
		newTestMonitoringMgr(),
		testGrpcConfig(),
		false)
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

	binaryPath := testBinary(t, "component")
	runtimeSpec := component.InputRuntimeSpec{
		InputType:  "fake",
		BinaryName: "",
		BinaryPath: binaryPath,
		Spec:       fakeInputSpec,
	}
	components := []component.Component{
		{
			ID:        "fake-0",
			InputSpec: &runtimeSpec,
			Units: []component.Unit{
				{
					ID:   "fake-input-0-0",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-0",
					}),
				},
				{
					ID:   "fake-input-0-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-1",
					}),
				},
				{
					ID:   "fake-input-0-2",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-2",
					}),
				},
			},
		},
		{
			ID:        "fake-1",
			InputSpec: &runtimeSpec,
			Units: []component.Unit{
				{
					ID:   "fake-input-1-0",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 1-0",
					}),
				},
				{
					ID:   "fake-input-1-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 1-1",
					}),
				},
				{
					ID:   "fake-input-1-2",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 1-2",
					}),
				},
			},
		},
		{
			ID:        "fake-2",
			InputSpec: &runtimeSpec,
			Units: []component.Unit{
				{
					ID:   "fake-input-2-0",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 2-0",
					}),
				},
				{
					ID:   "fake-input-2-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 2-1",
					}),
				},
				{
					ID:   "fake-input-2-2",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 2-2",
					}),
				},
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh0 := make(chan error)
	subErrCh1 := make(chan error)
	subErrCh2 := make(chan error)
	go func() {
		sub0 := m.Subscribe(subCtx, "fake-0")
		sub1 := m.Subscribe(subCtx, "fake-1")
		sub2 := m.Subscribe(subCtx, "fake-2")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub0.Ch():
				t.Logf("component fake-0 state changed: %+v", state)
				signalState(subErrCh0, &state, []client.UnitState{client.UnitStateHealthy})
			case state := <-sub1.Ch():
				t.Logf("component fake-1 state changed: %+v", state)
				signalState(subErrCh1, &state, []client.UnitState{client.UnitStateHealthy})
			case state := <-sub2.Ch():
				t.Logf("component fake-2 state changed: %+v", state)
				signalState(subErrCh2, &state, []client.UnitState{client.UnitStateHealthy})
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh0)
	defer drainErrChan(subErrCh1)
	defer drainErrChan(subErrCh2)

	m.Update(component.Model{Components: components})
	err = <-m.errCh
	require.NoError(t, err)

	count := 0
	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh0:
			require.NoError(t, err)
			count++
			if count >= 3 {
				break LOOP
			}
		case err := <-subErrCh1:
			require.NoError(t, err)
			count++
			if count >= 3 {
				break LOOP
			}
		case err := <-subErrCh2:
			require.NoError(t, err)
			count++
			if count >= 3 {
				break LOOP
			}
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func (suite *FakeInputSuite) TestManager_LogLevel() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai := &info.AgentInfo{}
	m, err := NewManager(
		newDebugLogger(t),
		newDebugLogger(t),
		ai,
		apmtest.DiscardTracer,
		newTestMonitoringMgr(),
		testGrpcConfig(),
		false)
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

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelInfo,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							updatedComp := comp
							updatedComp.Units = make([]component.Unit, len(comp.Units))
							copy(updatedComp.Units, comp.Units)
							updatedComp.Units[0] = component.Unit{
								ID:       "fake-input",
								Type:     client.UnitTypeInput,
								LogLevel: client.UnitLogLevelTrace,
								Config: component.MustExpectedConfig(map[string]interface{}{
									"type":    "fake",
									"state":   int(client.UnitStateHealthy),
									"message": "Fake Healthy",
								}),
							}

							actionCtx, actionCancel := context.WithTimeout(context.Background(), 5*time.Second)
							_, err := m.PerformAction(actionCtx, comp, comp.Units[0], "invalid_missing_action", nil)
							actionCancel()
							if err == nil {
								subErrCh <- fmt.Errorf("should have returned an error")
							} else if err.Error() != errActionUndefined {
								subErrCh <- fmt.Errorf("should have returned error: action undefined")
							} else {
								subErrCh <- nil
							}
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
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

func (suite *FakeInputSuite) TestManager_StartStopComponent() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log, logs := loggertest.New("TestManager_StartStopComponent")
	ai := &info.AgentInfo{}
	m, err := NewManager(
		log,
		newDebugLogger(t),
		ai,
		apmtest.DiscardTracer,
		newTestMonitoringMgr(),
		testGrpcConfig(),
		false)
	require.NoError(t, err, "could not crete new manager")

	managerErrCh := make(chan error)
	go func() {
		defer close(managerErrCh)
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		managerErrCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := waitForReady(waitCtx, m); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	runtimeSpec := component.InputRuntimeSpec{
		InputType:  "fake",
		BinaryName: "",
		BinaryPath: binaryPath,
		Spec:       fakeInputSpec,
	}
	const comp0ID = "fake-0"
	const comp1ID = "fake-1"

	components := []component.Component{
		{
			ID:        comp0ID,
			InputSpec: &runtimeSpec,
			Units: []component.Unit{
				{
					ID:   "fake-input-0-0",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-0",
					}),
				},
				{
					ID:   "fake-input-0-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-1",
					}),
				},
				{
					ID:   "fake-input-0-2",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-1",
					}),
				},
			},
		},
	}

	components2 := []component.Component{
		{
			ID:        comp1ID,
			InputSpec: &runtimeSpec,
			Units: []component.Unit{
				{
					ID:   "fake-input-1-0",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-0",
					}),
				},
				{
					ID:   "fake-input-1-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-1",
					}),
				},
				{
					ID:   "fake-input-1-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-1",
					}),
				},
			},
		},
	}

	select {
	case err := <-managerErrCh:
		require.NoError(t, err,
			"Manager.Run returned and error before 1st component update")
	default:
	}

	m.Update(component.Model{Components: components})
	err = <-m.errCh
	require.NoError(t, err, "expected no error from the manager when applying"+
		"the 1st component model")

	// Wait the 1st config to be applied and the comp0ID to start
	require.Eventuallyf(t,
		func() bool {
			filtered := logs.FilterMessageSnippet(
				fmt.Sprintf("Starting component %q", comp0ID)).
				TakeAll()
			return len(filtered) > 0
		},
		30*time.Second,
		200*time.Millisecond,
		"component %s did not start", comp0ID)

	m.Update(component.Model{Components: components2})
	err = <-m.errCh
	require.NoError(t, err, "expected no error from the manager when applying"+
		"the 2nd component model")

	// Wait the 2nd config to be applied and the comp1ID to start
	require.Eventuallyf(t,
		func() bool {
			filtered := logs.FilterMessageSnippet(
				fmt.Sprintf("Starting component %q", comp1ID)).
				TakeAll()
			return len(filtered) > 0
		},
		30*time.Second,
		200*time.Millisecond,
		"component %s did not start", comp1ID)

	// component 1 started, we can stop the manager
	cancel()

	comp0StartLogs := logs.FilterMessageSnippet(
		fmt.Sprintf("Starting component %q", comp0ID)).TakeAll()
	comp0StopLogs := logs.FilterMessageSnippet(
		fmt.Sprintf("Stopping component %q", comp0ID)).TakeAll()
	comp1StartLogs := logs.FilterMessageSnippet(
		fmt.Sprintf("Starting component %q", comp1ID)).TakeAll()

	assert.Len(t, comp0StartLogs, 1,
		"component %d started more than once", comp0ID)
	assert.Len(t, comp0StopLogs, 1,
		"component %d stopped more than once", comp0ID)
	assert.Len(t, comp1StartLogs, 1,
		"component %d started more than once", comp1ID)

	assert.Truef(t, comp0StopLogs[0].Time.Before(comp1StartLogs[0].Time),
		"component %s stopped after %s", comp0ID, comp1ID)

	err = <-managerErrCh
	assert.NoError(t, err, "Manager.Run returned and error")

	if t.Failed() {
		t.Logf("manager logs:")
		for _, l := range logs.TakeAll() {
			t.Log(l)
		}
	}
}

func (suite *FakeInputSuite) TestManager_Chunk() {
	t := suite.T()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const grpcDefaultSize = 1024 * 1024 * 4
	grpcConfig := testGrpcConfig()
	grpcConfig.MaxMsgSize = grpcDefaultSize * 2 // set to double the default size

	ai := &info.AgentInfo{}
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), ai, apmtest.DiscardTracer, newTestMonitoringMgr(), grpcConfig, false)
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	// build the units to ensure that there is more than double the units required for the GRPC configuration
	minimumMsgSize := int(float64(grpcConfig.MaxMsgSize) * 1.2) // increase by 20%
	var units []component.Unit
	var unitsSize int
	var nextUnitID int
	for {
		unit := component.Unit{
			ID:       fmt.Sprintf("fake-input-%d", nextUnitID),
			Type:     client.UnitTypeInput,
			LogLevel: client.UnitLogLevelError,
			Config: component.MustExpectedConfig(map[string]interface{}{
				"type":    "fake",
				"state":   int(client.UnitStateHealthy),
				"message": fmt.Sprintf("Fake Healthy %d", nextUnitID),
				"payload": map[string]interface{}{
					"fake-id":    nextUnitID,
					"extra-data": fmt.Sprintf("extra data for the unit %d to make it some what larger", nextUnitID),
				},
			}),
		}
		unitExpected := proto.UnitExpected{
			Id:             unit.ID,
			Type:           proto.UnitType_INPUT,
			State:          proto.State_HEALTHY,
			ConfigStateIdx: 1,
			Config:         unit.Config,
			LogLevel:       proto.UnitLogLevel_ERROR,
		}
		units = append(units, unit)
		unitsSize += gproto.Size(&unitExpected)
		nextUnitID++

		if unitsSize > minimumMsgSize {
			break
		}
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: units,
	}

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := waitForReady(waitCtx, m); err != nil {
		require.NoError(t, err)
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					healthyCount := 0
					stoppedCount := 0
					for _, unit := range state.Units {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							healthyCount += 1
						} else if unit.State == client.UnitStateStopped {
							stoppedCount += 1
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					}
					if healthyCount == len(units) {
						// remove the component which will stop it
						m.Update(component.Model{Components: []component.Component{}})
						err := <-m.errCh
						if err != nil {
							subErrCh <- err
						}
					} else if stoppedCount == len(units) {
						subErrCh <- nil
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	m.Update(component.Model{Components: []component.Component{comp}})
	err = <-m.errCh
	require.NoError(t, err)

	endTimer := time.NewTimer(6 * time.Minute) // very large number of units will take time
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 6 minutes")
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

	workDir := filepath.Join(paths.Run(), comp.ID)
	_, err = os.Stat(workDir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func signalState(subErrCh chan error, state *ComponentState, acceptableStates []client.UnitState) {
	if state.State == client.UnitStateFailed {
		subErrCh <- fmt.Errorf("component failed: %s", state.Message)
		return
	}

	var issues []string
	healthy := 0
	for key, unit := range state.Units {
		switch {
		case unit.State == client.UnitStateStarting:
		// acceptable, but does not count as health
		case isValidState(unit.State, acceptableStates):
			healthy++
		default:

			issues = append(issues, fmt.Sprintf(
				"unit %s in invalid state %v", key.UnitID, unit.State))
		}
	}

	if len(issues) != 0 {
		subErrCh <- errors.New(strings.Join(issues, "| "))
	}

	if healthy == len(state.Units) {
		subErrCh <- nil
	}
}

func isValidState(state client.UnitState, acceptableStates []client.UnitState) bool {
	for _, s := range acceptableStates {
		if s == state {
			return true
		}
	}
	return false
}

func testBinary(t *testing.T, name string) string {
	t.Helper()

	var err error
	binaryPath := fakeBinaryPath(name)

	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		t.Fatalf("failed abs %s: %s", binaryPath, err)
	}

	return binaryPath
}

func testGrpcConfig() *configuration.GRPCConfig {
	grpcConfig := configuration.DefaultGRPCConfig()
	grpcConfig.Port = 0 // this means that we choose a random available port
	return grpcConfig
}

func fakeBinaryPath(name string) string {
	binaryPath := filepath.Join("..", "fake", name, name)

	if runtime.GOOS == component.Windows {
		binaryPath += exeExt
	}

	return binaryPath
}

func timedWaitForReady(t *testing.T, m *Manager, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := waitForReady(ctx, m)
	if err != nil {
		require.FailNow(t, "timed out waiting for Manager to start")
	}
}
