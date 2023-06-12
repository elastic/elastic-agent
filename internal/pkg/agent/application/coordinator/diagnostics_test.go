// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator_test

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/stretchr/testify/assert"
	mock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/atomic"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/mocks"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Refer to https://vektra.github.io/mockery/installation/ to check how to install mockery binary
//go:generate mockery --name ComponentsModifier
//go:generate mockery --name ConfigChange
//go:generate mockery --name RuntimeManager
//go:generate mockery --name ConfigManager
//go:generate mockery --name VarsManager
//go:generate mockery --name UpgradeManager
//go:generate mockery --name ReExecManager
//go:generate mockery --name MonitorManager
//go:generate mockery --dir ../../../capabilities/ --name Capability
//go:generate mockery --dir ../../../core/composable/ --name FetchContextProvider

var /*const*/ expectedDiagnosticHooks map[string]string = map[string]string{
	"local-config":        "local-config.yaml",
	"pre-config":          "pre-config.yaml",
	"variables":           "variables.yaml",
	"computed-config":     "computed-config.yaml",
	"components-expected": "components-expected.yaml",
	"components-actual":   "components-actual.yaml",
	"state":               "state.yaml",
}

var /*const*/ linuxPlatformDetail component.PlatformDetail = component.PlatformDetail{
	Platform: component.Platform{
		OS:   "linux",
		Arch: "amd64",
		GOOS: "linux",
	},
	Family: "",
	Major:  "22",
	Minor:  "4",
}

type MockedUnit struct {
	ID       string              `yaml:"id"`
	LogLevel client.UnitLogLevel `yaml:"log_level"`
	Type     client.UnitType     `yaml:"type"`
	Config   map[string]any      `yaml:"config"`
}

// MockedComponentsUnits is a simple structure to unmarshal the values
// returned by the mocked Runtime Manager as components and units being run
type MockedComponentsUnits struct {
	ID    string       `yaml:"id"`
	CType string       `yaml:"type"`
	Units []MockedUnit `yaml:"units"`
}

func TestCoordinatorDiagnosticHooks(t *testing.T) {

	type testCase struct {
		name                    string
		runtimeSpecsPath        string
		platform                component.PlatformDetail
		configFilePath          string
		componentsUnitsFilePath string
		componentsState         func(*testing.T, *component.RuntimeSpecs, string) []runtime.ComponentComponentState
		varsProvider            func(*testing.T) []*transpiler.Vars
		expectedDiagnosticsPath string
	}

	testcases := []testCase{
		{
			name:                    "Default Fleet Policy",
			runtimeSpecsPath:        filepath.Join("..", "..", "..", "..", "..", "specs"),
			platform:                linuxPlatformDetail,
			configFilePath:          filepath.Join(".", "testdata", "simple_config", "elastic-agent.yml"),
			componentsUnitsFilePath: filepath.Join(".", "testdata", "simple_config", "mocked_components_units.yaml"),
			componentsState: func(t *testing.T, specs *component.RuntimeSpecs, componentsUnitsFilePath string) []runtime.ComponentComponentState {

				componentsBytes, err := os.ReadFile(componentsUnitsFilePath)
				require.NoError(t, err)
				mockedComponents := make([]MockedComponentsUnits, 0, 5)
				err = yaml.Unmarshal(componentsBytes, &mockedComponents)
				require.NoError(t, err)

				componentStates := make([]runtime.ComponentComponentState, 0, len(mockedComponents))

				for _, comp := range mockedComponents {

					// create all the units for the component
					units := make([]component.Unit, 0, len(comp.Units))
					unitsStates := map[runtime.ComponentUnitKey]runtime.ComponentUnitState{}
					for _, mockedUnit := range comp.Units {
						// FIXME: when trying to create the proto struct values from map, we panic trying to create the "source" attribute
						require.NoErrorf(t, err, "Error parsing unit expected config for component %q unit %q", comp.ID, mockedUnit.ID)
						units = append(units, component.Unit{
							ID:       mockedUnit.ID,
							Type:     mockedUnit.Type,
							LogLevel: mockedUnit.LogLevel,
							// Config:   mockedUnit.Config,
						})
						// FIXME this composite key is ok for Marshaling but then Unmarshaling into a generic map[any]any returns error,
						// hence we cannot properly sanitize hook output - A custom unmarshaler would probably solve this
						// unitStateKey := runtime.ComponentUnitKey{UnitType: mockedUnit.Type, UnitID: mockedUnit.ID}
						// unitsStates[unitStateKey] = runtime.ComponentUnitState{
						// 	State:   client.UnitStateHealthy,
						// 	Message: "Healthy",
						// }
					}

					//create the component itself
					spec, err := specs.GetInput(comp.CType)
					require.NoErrorf(t, err, "unknown spec for component with id %q and type %q", comp.ID, comp.CType)

					componentState := runtime.ComponentComponentState{
						Component: component.Component{
							ID:        comp.ID,
							InputSpec: &spec,
							Units:     units,
						},
						State: runtime.ComponentState{
							State: client.UnitStateHealthy,
							VersionInfo: runtime.ComponentVersionInfo{
								Name:    fmt.Sprintf("Mock %s", comp.CType),
								Version: "1.2.3",
							},
							Units: unitsStates,
							Features: &proto.Features{
								Fqdn: &proto.FQDNFeature{Enabled: true},
							},
							FeaturesIdx: 1,
						},
					}

					componentStates = append(componentStates, componentState)
				}
				return componentStates
			},
			varsProvider: func(t *testing.T) []*transpiler.Vars {
				//Provide vars
				processors := transpiler.Processors{
					{
						"add_fields": map[string]interface{}{
							"dynamic": "added",
						},
					},
				}
				fetchContextProvider := mocks.NewFetchContextProvider(t)
				fetchContextProviders := mapstr.M{
					"kubernetes_secrets": fetchContextProvider,
				}
				vars, err := transpiler.NewVarsWithProcessors(
					"id",
					map[string]interface{}{
						"host": map[string]interface{}{"platform": "linux"},
						"dynamic": map[string]interface{}{
							"key1": "dynamic1",
							"list": []string{
								"array1",
								"array2",
							},
							"dict": map[string]string{
								"key1": "value1",
								"key2": "value2",
							},
						},
					},
					"dynamic",
					processors,
					fetchContextProviders)
				require.NoError(t, err)
				return []*transpiler.Vars{vars}
			},
			expectedDiagnosticsPath: filepath.Join(".", "testdata", "simple_config", "expected"),
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			specs, err := component.LoadRuntimeSpecs(
				tt.runtimeSpecsPath,
				tt.platform,
				component.SkipBinaryCheck(),
			)
			require.NoError(t, err)

			helper := newCoordinatorTestHelper(t, &info.AgentInfo{}, specs, false)

			ctx, cancelFunc := context.WithCancel(context.Background())
			componentsUpdateChannel := make(chan runtime.ComponentComponentState)
			subscriptionAll := runtime.NewSubscriptionAllWithChannel(ctx, componentsUpdateChannel)
			helper.runtimeManager.EXPECT().SubscribeAll(mock.Anything).Return(subscriptionAll)
			helper.runtimeManager.EXPECT().Update(mock.AnythingOfType("component.Model")).Return(nil)

			sut := helper.coordinator
			coordinatorWg := new(sync.WaitGroup)
			defer func() {
				cancelFunc()
				// wait till the coordinator exits to avoid a panic
				// when logging after the test goroutine exited
				coordinatorWg.Wait()
			}()

			coordinatorWg.Add(1)
			go func() {
				defer coordinatorWg.Done()
				coordErr := sut.Run(ctx)
				assert.ErrorIs(t, coordErr, context.Canceled, "Coordinator exited with unexpected error")
			}()

			mustWriteToChannelBeforeTimeout(t, tt.varsProvider(t), helper.varsChannel, 100*time.Millisecond)

			// Inject initial configuration - after starting coordinator
			configBytes, err := os.ReadFile(tt.configFilePath)
			require.NoError(t, err)

			initialConf := config.MustNewConfigFrom(configBytes)

			// These flags are set in callbacks from the Coordinator goroutine
			// when the mocked functions are invoked, so we can tell in the
			// assertions below when it's safe to advance to the next stage of
			// the test.
			configCalled := atomic.NewBool(false)
			ackCalled := atomic.NewBool(false)

			initialConfChange := mocks.NewConfigChange(t)
			initialConfChange.EXPECT().Config().RunAndReturn(func() *config.Config {
				configCalled.Store(true)
				return initialConf
			})
			initialConfChange.EXPECT().Ack().RunAndReturn(func() error {
				ackCalled.Store(true)
				return nil
			}).Times(1)
			mustWriteToChannelBeforeTimeout[coordinator.ConfigChange](t, initialConfChange, helper.configChangeChannel, 100*time.Millisecond)

			assert.Eventually(t, func() bool {
				return sut.State().State == cproto.State_HEALTHY
			}, 1*time.Second, 50*time.Millisecond)
			assert.Eventually(t, func() bool {
				return configCalled.Load() && ackCalled.Load()
			}, 1*time.Second, 50*time.Millisecond)
			t.Logf("Agent state: %s", sut.State().State)

			// Send runtime component state
			componentStates := tt.componentsState(t, &specs, tt.componentsUnitsFilePath)
			for _, componentState := range componentStates {
				mustWriteToChannelBeforeTimeout(t, componentState, componentsUpdateChannel, 100*time.Millisecond)
			}

			// FIXME there's no way to know if the coordinator processed the runtime component states, wait and hope for the best
			time.Sleep(50 * time.Millisecond)

			diagHooks := sut.DiagnosticHooks()
			t.Logf("Received diagnostics: %+v", diagHooks)
			assert.NotEmpty(t, diagHooks)

			hooksNames := make([]string, 0, len(diagHooks))
			hooksMap := map[string]diagnostics.Hook{}
			for i, h := range diagHooks {
				hooksNames = append(hooksNames, h.Name)
				hooksMap[h.Name] = diagHooks[i]
			}

			expectedNames := make([]string, 0, len(expectedDiagnosticHooks))
			for n := range expectedDiagnosticHooks {
				expectedNames = append(expectedNames, n)
			}

			require.ElementsMatch(t, expectedNames, hooksNames)
			for hookName, diagFileName := range expectedDiagnosticHooks {
				if !assert.Contains(t, hooksMap, hookName) {
					continue // this iteration failed, no reason to do further tests, moving forward
				}

				hook := hooksMap[hookName]
				assert.Equal(t, diagFileName, hook.Filename)
				hookResult := hook.Hook(ctx)
				stringHookResult := sanitizeHookResult(t, hook.Filename, hook.ContentType, hookResult)
				// The output of hooks is VERY verbose even for simple configs but useful for debugging
				t.Logf("\n--- #--- File %[1]s START ---#\n%[2]s\n--- #--- File %[1]s END ---#", hook.Filename, stringHookResult)
				expectedbytes, err := os.ReadFile(fmt.Sprintf("./testdata/simple_config/expected/%s", hook.Filename))
				if assert.NoError(t, err) {
					assert.YAMLEqf(t, string(expectedbytes), stringHookResult, "Unexpected YAML content for file %s", hook.Filename)
				}
			}
		})
	}
}

// sanitizeHookResult will try to get rid of all the specific part of hooks output that may vary from one run to another
// on different machines. The sanitized result is then compared against the expected outputs (and this content should be the same
// no matter the OS, version, path separator etc.)
// More specifically:
//
// for yaml content type:
//   - we remove the runtime informations (we just check that they are present)
//   - we replace the cwd where the test is running with the "<AgentRunDir>" placeholder
//   - we replace the hostId with the "<HostID>" placeholder
//   - we transform all paths to forward slash separated using filepath.ToSlash (sorry Windows 😅)
//
// for non-yaml content type:
//   - we replace the cwd where the test is running with the "<AgentRunDir>" placeholder (it's a best effort thing)
func sanitizeHookResult(t *testing.T, fileName string, contentType string, rawBytes []byte) (retVal string) {
	const agentPathPlaceholder string = "<AgentRunDir>"
	const hostIDPlaceholder string = "<HostID>"
	const hostKey = "host"
	const pathKey = "path"

	if contentType != "application/yaml" {
		//substitute current running dir with a placeholder
		testDir := path.Dir(os.Args[0])
		t.Logf("Replacing test dir %s with %s", testDir, agentPathPlaceholder)
		return strings.ReplaceAll(string(rawBytes), testDir, agentPathPlaceholder)
	}

	switch fileName {
	case "pre-config.yaml", "computed-config.yaml":
		yamlContent := map[any]any{}
		err := yaml.Unmarshal(rawBytes, &yamlContent)
		assert.NoErrorf(t, err, "file %s is invalid YAML", fileName)

		// get rid of runtime informations, since those depend on the machine where the test is executed, just assert that they exist
		assert.Containsf(t, yamlContent, "runtime", "No runtime information found in YAML")
		delete(yamlContent, "runtime")

		// fix id and directories
		if assert.Containsf(t, yamlContent, hostKey, "config yaml does not contain %s key", hostKey) {
			hostValue := yamlContent[hostKey]
			if assert.IsType(t, map[interface{}]interface{}{}, hostValue) {
				hostMap := hostValue.(map[interface{}]interface{})
				if assert.Contains(t, hostMap, "id", "host map does not contain id") {
					t.Logf("Substituting host id %q with %q", hostMap["id"], hostIDPlaceholder)
					hostMap["id"] = hostIDPlaceholder
				}
			}
		}

		if assert.Containsf(t, yamlContent, pathKey, "config yaml does not contain agent path map") {
			pathValue := yamlContent[pathKey]
			if assert.IsType(t, map[interface{}]interface{}{}, pathValue) {
				pathMap := pathValue.(map[interface{}]interface{})
				currentDir := pathMap["config"].(string)
				for _, key := range []string{"config", "data", "home", "logs"} {
					if assert.Containsf(t, pathMap, key, "path map is missing expected key %q", key) {
						value := pathMap[key]
						if assert.IsType(t, "", value) {
							valueString := value.(string)
							valueString = strings.Replace(valueString, currentDir, agentPathPlaceholder, 1)
							pathMap[key] = filepath.ToSlash(valueString)
						}
					}
				}
			}
		}
		sanitizedBytes, err := yaml.Marshal(yamlContent)
		assert.NoError(t, err)
		return string(sanitizedBytes)

	case "components-expected.yaml", "components-actual.yaml":
		yamlContent := map[any]any{}
		err := yaml.Unmarshal(rawBytes, &yamlContent)
		assert.NoErrorf(t, err, "file %s is invalid YAML", fileName)

		rawComponents, ok := yamlContent["components"].([]any)

		if assert.True(t, ok, "unexpected component format in file %s", fileName) {
			sort.Sort(SortByID(rawComponents))
			// fix the paths to forward slash for each
			for _, comp := range rawComponents {
				compInputSpec := comp.(map[any]any)["input_spec"].(map[any]any)
				compInputSpec["binary_path"] = filepath.ToSlash(compInputSpec["binary_path"].(string))
			}
			yamlContent["components"] = rawComponents
		}
		sanitizedBytes, err := yaml.Marshal(yamlContent)
		assert.NoError(t, err)
		return string(sanitizedBytes)
	}

	return string(rawBytes)
}

// SortByID makes an array of map[any]any sortable by the "id" property
// It's used to stabilize the order in which some items in a YAML array
// appear in a diagnostic hook output.
// If we cannot cast the elements to maps or if the "id" property is not
// a string, this will panic (should never happen for our outputs)
type SortByID []any

func (a SortByID) Len() int      { return len(a) }
func (a SortByID) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a SortByID) Less(i, j int) bool {
	iID := a[i].(map[any]any)["id"].(string)
	jID := a[j].(map[any]any)["id"].(string)
	return iID < jID
}

type coordinatorTestHelper struct {
	coordinator *coordinator.Coordinator

	runtimeManager      *mocks.RuntimeManager
	runtimeErrorChannel chan error

	configManager       *mocks.ConfigManager
	configChangeChannel chan coordinator.ConfigChange
	configErrorChannel  chan error
	actionErrorChannel  chan error

	varsManager      *mocks.VarsManager
	varsChannel      chan []*transpiler.Vars
	varsErrorChannel chan error

	capability     *mocks.Capability
	upgradeManager *mocks.UpgradeManager
	reExecManager  *mocks.ReExecManager
	monitorManager *mocks.MonitorManager
}

func newCoordinatorTestHelper(t *testing.T, agentInfo *info.AgentInfo, specs component.RuntimeSpecs, isManaged bool) *coordinatorTestHelper {
	t.Helper()

	helper := new(coordinatorTestHelper)

	// Runtime manager basic wiring
	mockRuntimeMgr := mocks.NewRuntimeManager(t)
	runtimeErrChan := make(chan error)
	mockRuntimeMgr.EXPECT().Errors().Return(runtimeErrChan)
	mockRuntimeMgr.EXPECT().Run(mock.Anything).RunAndReturn(func(_ctx context.Context) error { <-_ctx.Done(); return _ctx.Err() }).Times(1)
	helper.runtimeManager = mockRuntimeMgr
	helper.runtimeErrorChannel = runtimeErrChan

	// Config manager basic wiring
	mockConfigMgr := mocks.NewConfigManager(t)
	configErrChan := make(chan error)
	mockConfigMgr.EXPECT().Errors().Return(configErrChan)
	actionErrorChan := make(chan error)
	mockConfigMgr.EXPECT().ActionErrors().Return(actionErrorChan)
	configChangeChan := make(chan coordinator.ConfigChange)
	mockConfigMgr.EXPECT().Watch().Return(configChangeChan)
	mockConfigMgr.EXPECT().Run(mock.Anything).RunAndReturn(func(_ctx context.Context) error { <-_ctx.Done(); return _ctx.Err() }).Times(1)
	helper.configManager = mockConfigMgr
	helper.configErrorChannel = configErrChan
	helper.actionErrorChannel = actionErrorChan
	helper.configChangeChannel = configChangeChan

	//Variables manager basic wiring
	mockVarsMgr := mocks.NewVarsManager(t)
	varsErrChan := make(chan error)
	mockVarsMgr.EXPECT().Errors().Return(varsErrChan)
	varsChan := make(chan []*transpiler.Vars)
	mockVarsMgr.EXPECT().Watch().Return(varsChan)
	mockVarsMgr.EXPECT().Run(mock.Anything).RunAndReturn(func(_ctx context.Context) error { <-_ctx.Done(); return _ctx.Err() }).Times(1)
	helper.varsManager = mockVarsMgr
	helper.varsChannel = varsChan
	helper.varsErrorChannel = varsErrChan

	//Capability basic wiring
	mockCapability := mocks.NewCapability(t)
	mockCapability.EXPECT().Apply(mock.AnythingOfType("*transpiler.AST")).RunAndReturn(func(in interface{}) (interface{}, error) { return in, nil })
	helper.capability = mockCapability

	// Upgrade manager
	mockUpgradeMgr := mocks.NewUpgradeManager(t)
	mockUpgradeMgr.EXPECT().Reload(mock.AnythingOfType("*config.Config")).Return(nil)
	// mockUpgradeMgr.EXPECT().Upgradeable().Return(false)
	helper.upgradeManager = mockUpgradeMgr

	//ReExec manager
	helper.reExecManager = mocks.NewReExecManager(t)

	//Monitor manager
	mockMonitorMgr := mocks.NewMonitorManager(t)
	mockMonitorMgr.EXPECT().Reload(mock.AnythingOfType("*config.Config")).Return(nil)
	mockMonitorMgr.EXPECT().Enabled().Return(false)
	helper.monitorManager = mockMonitorMgr

	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.ToStderr = true

	log, err := logger.NewFromConfig("coordinator-test", loggerCfg, false)
	require.NoError(t, err)

	cfg := configuration.DefaultConfiguration()
	cfg.Settings.DownloadConfig.InstallPath = "install"
	cfg.Settings.DownloadConfig.TargetDirectory = "target"
	cfg.Settings.LoggingConfig.Files.Path = "logs"

	helper.coordinator = coordinator.New(
		log,
		cfg,
		logp.InfoLevel,
		agentInfo,
		specs,
		helper.reExecManager,
		helper.upgradeManager,
		helper.runtimeManager,
		helper.configManager,
		helper.varsManager,
		helper.capability,
		helper.monitorManager,
		isManaged,
	)

	return helper
}

func mustWriteToChannelBeforeTimeout[V any](t *testing.T, value V, channel chan V, timeout time.Duration) {
	timer := time.NewTimer(timeout)

	select {
	case channel <- value:
		if !timer.Stop() {
			<-timer.C
		}
		t.Logf("%T written", value)
	case <-timer.C:
		t.Fatalf("Timeout writing %T", value)
	}
}
