// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"

	"go.elastic.co/apm"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/limits"
	"github.com/elastic/elastic-agent/pkg/utils/broadcaster"
)

// ErrNotUpgradable error is returned when upgrade cannot be performed.
var ErrNotUpgradable = errors.New(
	"cannot be upgraded; must be installed with install sub-command and " +
		"running under control of the systems supervisor")

// ErrUpgradeInProgress error is returned if two or more upgrades are
// attempted at the same time.
var ErrUpgradeInProgress = errors.New("upgrade already in progress")

// ReExecManager provides an interface to perform re-execution of the entire agent.
type ReExecManager interface {
	ReExec(callback reexec.ShutdownCallbackFn, argOverrides ...string)
}

// UpgradeManager provides an interface to perform the upgrade action for the agent.
type UpgradeManager interface {
	// Upgradeable returns true if can be upgraded.
	Upgradeable() bool

	// Reload reloads the configuration for the upgrade manager.
	Reload(rawConfig *config.Config) error

	// Upgrade upgrades running agent.
	Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, details *details.Details, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error)

	// Ack is used on startup to check if the agent has upgraded and needs to send an ack for the action
	Ack(ctx context.Context, acker acker.Acker) error

	// MarkerWatcher returns a watcher for the upgrade marker.
	MarkerWatcher() upgrade.MarkerWatcher

	// Close releases any resources in use by the UpgradeManager
	Close() error
}

// MonitorManager provides an interface to perform the monitoring action for the agent.
type MonitorManager interface {
	// Enabled when configured to collect metrics/logs.
	Enabled() bool

	// Reload reloads the configuration for the upgrade manager.
	Reload(rawConfig *config.Config) error

	// MonitoringConfig injects monitoring configuration into resolved ast tree.
	MonitoringConfig(map[string]interface{}, []component.Component, map[string]string) (map[string]interface{}, error)
}

// Runner provides interface to run a manager and receive running errors.
type Runner interface {
	// Run runs the manager.
	Run(context.Context) error

	// Errors returns the channel to listen to errors on.
	//
	// A manager should send a nil error to clear its previous error when it should no longer report as an error.
	Errors() <-chan error
}

// RuntimeManager provides an interface to run and update the runtime.
type RuntimeManager interface {
	Runner

	// Update updates the current components model.
	Update(model component.Model) error

	// State returns the current components model state.
	State() []runtime.ComponentComponentState

	// PerformAction executes an action on a unit.
	PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error)

	// SubscribeAll provides an interface to watch for changes in all components.
	SubscribeAll(context.Context) *runtime.SubscriptionAll

	// PerformDiagnostics executes the diagnostic action for the provided units. If no units are provided then
	// it performs diagnostics for all current units.
	PerformDiagnostics(context.Context, ...runtime.ComponentUnitDiagnosticRequest) []runtime.ComponentUnitDiagnostic

	// PerformComponentDiagnostics executes the diagnostic action for the provided components. If no components are provided,
	// then it performs the diagnostics for all current units.
	PerformComponentDiagnostics(ctx context.Context, additionalMetrics []cproto.AdditionalDiagnosticRequest, req ...component.Component) ([]runtime.ComponentDiagnostic, error)
}

// ConfigChange provides an interface for receiving a new configuration.
//
// Ack must be called if the configuration change was accepted and Fail should be called if it fails to be accepted.
type ConfigChange interface {
	// Config returns the configuration for this change.
	Config() *config.Config

	// Ack marks the configuration change as accepted.
	Ack() error

	// Fail marks the configuration change as failed.
	Fail(err error)
}

// ErrorReporter provides an interface for any manager that is handled by the coordinator to report errors.
type ErrorReporter interface{}

// ConfigManager provides an interface to run and watch for configuration changes.
type ConfigManager interface {
	Runner

	// ActionErrors returns the error channel for actions.
	// May return errors for fleet managed agents.
	// Will always be empty for standalone agents.
	ActionErrors() <-chan error

	// Watch returns the chanel to watch for configuration changes.
	Watch() <-chan ConfigChange
}

// VarsManager provides an interface to run and watch for variable changes.
type VarsManager interface {
	Runner

	// Watch returns the chanel to watch for variable changes.
	Watch() <-chan []*transpiler.Vars
}

// ComponentsModifier is a function that takes the computed components model and modifies it before
// passing it into the components runtime manager.
type ComponentsModifier func(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error)

// managerShutdownTimeout is how long the coordinator will wait during shutdown
// to receive termination states from its managers.
const managerShutdownTimeout = time.Second * 5

type configReloader interface {
	Reload(*config.Config) error
}

// Coordinator manages the entire state of the Elastic Agent.
//
// All configuration changes, update variables, and upgrade actions are managed and controlled by the coordinator.
type Coordinator struct {
	logger    *logger.Logger
	agentInfo *info.AgentInfo
	isManaged bool

	cfg   *configuration.Configuration
	specs component.RuntimeSpecs

	reexecMgr  ReExecManager
	upgradeMgr UpgradeManager
	monitorMgr MonitorManager

	monitoringServerReloader configReloader

	runtimeMgr RuntimeManager
	configMgr  ConfigManager
	varsMgr    VarsManager

	caps      capabilities.Capabilities
	modifiers []ComponentsModifier

	// The current state of the Coordinator. This value and its subfields are
	// safe to read directly from within the main Coordinator goroutine.
	// Changes are also safe but must set the stateNeedsRefresh flag to ensure
	// an update is broadcast at the end of the current iteration (so it is
	// recommended to make changes via helper funtions like setCoordinatorState,
	// setFleetState, etc). Changes that need to broadcast immediately without
	// waiting for the end of the iteration can call stateRefresh() directly,
	// but this should be rare.
	//
	// state should never be directly read or written outside the Coordinator
	// goroutine. Callers who need to access or modify the state should use the
	// public accessors like State(), SetLogLevel(), etc.
	state            State
	stateBroadcaster *broadcaster.Broadcaster[State]

	// If you get a race detector error while accessing this field, it probably
	// means you're calling private Coordinator methods from outside the
	// Coordinator goroutine.
	stateNeedsRefresh bool

	// overrideState is used during the update process to report the overall
	// upgrade progress instead of the Coordinator's baseline internal state.
	overrideState *coordinatorOverrideState

	// overrideStateChan forwards override states from the publicly accessible
	// SetOverrideState helper to the Coordinator goroutine.
	overrideStateChan chan *coordinatorOverrideState

	// upgradeDetailsChan forwards upgrade details from the publicly accessible
	// SetUpgradeDetails helper to the Coordinator goroutine.
	upgradeDetailsChan chan *details.Details

	// loglevelCh forwards log level changes from the public API (SetLogLevel)
	// to the run loop in Coordinator's main goroutine.
	logLevelCh chan logp.Level

	// managerChans collects the channels used to receive updates from the
	// various managers. Coordinator reads from all of them during the run loop.
	// Tests can safely override these before calling Coordinator.Run, or in
	// between calls to Coordinator.runLoopIteration when testing synchronously.
	// Tests can send to these channels to simulate manager updates.
	managerChans managerChans

	// Top-level errors reported by managers / actions. These will be folded
	// into the reported state before broadcasting -- State() will report
	// agentclient.Failed if one of these is set, even if the underlying
	// coordinator state is agentclient.Healthy.
	runtimeMgrErr error // Currently unused
	configMgrErr  error
	actionsErr    error
	varsMgrErr    error

	// Errors resulting from different possible failure modes when setting a
	// new policy. Right now there are three different stages where a policy
	// update can fail:
	// - in generateAST, converting the policy to an AST
	// - in process, converting the AST and vars into a full component model
	// - while sending the final component model to the runtime manager
	//
	// The plan is to improve our preprocessing so we can always detect
	// failures immediately https://github.com/elastic/elastic-agent/issues/2887.
	// For now, we track three distinct errors for those three failure types,
	// and merge them into a readable error in generateReportableState.
	configErr        error
	componentGenErr  error
	runtimeUpdateErr error

	// The raw policy before spec lookup or variable substitution
	ast *transpiler.AST

	// The current variables
	vars []*transpiler.Vars

	// The policy after spec and variable substitution
	derivedConfig map[string]interface{}

	// The final component model generated from ast and vars (this is the same
	// value that is sent to the runtime manager).
	componentModel []component.Component

	// Disabled for 8.8.0 release in order to limit the surface
	// https://github.com/elastic/security-team/issues/6501

	// mx         sync.RWMutex
	// protection protection.Config
}

// The channels Coordinator reads to receive updates from the various managers.
type managerChans struct {
	// runtimeManagerUpdate is not read-only because it is owned internally
	// and written to by watchRuntimeComponents in a helper goroutine after
	// receiving updates from the raw runtime manager channel.
	runtimeManagerUpdate chan runtime.ComponentComponentState
	runtimeManagerError  <-chan error

	configManagerUpdate <-chan ConfigChange
	configManagerError  <-chan error
	actionsError        <-chan error

	varsManagerUpdate <-chan []*transpiler.Vars
	varsManagerError  <-chan error

	upgradeMarkerUpdate <-chan upgrade.UpdateMarker
	upgradeMarkerErr    <-chan error
}

// New creates a new coordinator.
func New(logger *logger.Logger, cfg *configuration.Configuration, logLevel logp.Level, agentInfo *info.AgentInfo, specs component.RuntimeSpecs, reexecMgr ReExecManager, upgradeMgr UpgradeManager, runtimeMgr RuntimeManager, configMgr ConfigManager, varsMgr VarsManager, caps capabilities.Capabilities, monitorMgr MonitorManager, isManaged bool, modifiers ...ComponentsModifier) *Coordinator {
	var fleetState cproto.State
	var fleetMessage string
	if !isManaged {
		// default enum value is STARTING which is confusing for standalone
		fleetState = agentclient.Stopped
		fleetMessage = "Not enrolled into Fleet"
	}
	state := State{
		State:        agentclient.Starting,
		Message:      "Starting",
		FleetState:   fleetState,
		FleetMessage: fleetMessage,
		LogLevel:     logLevel,
	}
	c := &Coordinator{
		logger:     logger,
		cfg:        cfg,
		agentInfo:  agentInfo,
		isManaged:  isManaged,
		specs:      specs,
		reexecMgr:  reexecMgr,
		upgradeMgr: upgradeMgr,
		monitorMgr: monitorMgr,
		runtimeMgr: runtimeMgr,
		configMgr:  configMgr,
		varsMgr:    varsMgr,
		caps:       caps,
		modifiers:  modifiers,
		state:      state,
		// Note: the uses of a buffered input channel in our broadcaster (the
		// third parameter to broadcaster.New) means that it is possible for
		// immediately adjacent writes/reads not to match, e.g.:
		//
		//  stateBroadcaster.Set(newState)
		//  reportedState := stateBroadcaster.Get()  // may not match newState
		//
		// We accept this intentionally to make sure Coordinator itself blocks
		// as rarely as possible. Within Coordinator's goroutine, we can always
		// get the latest synchronized value by reading the state struct directly,
		// so this only affects external callers, and we accept that some of those
		// might be behind by a scheduler interrupt or so.
		//
		// If this ever changes and we decide we need absolute causal
		// synchronization in the subscriber API, just set the input buffer to 0.
		stateBroadcaster: broadcaster.New(state, 64, 32),

		logLevelCh:         make(chan logp.Level),
		overrideStateChan:  make(chan *coordinatorOverrideState),
		upgradeDetailsChan: make(chan *details.Details),
	}
	// Setup communication channels for any non-nil components. This pattern
	// lets us transparently accept nil managers / simulated events during
	// unit testing.
	if runtimeMgr != nil {
		// The runtime manager's update channel is a special case: unlike the
		// other channels, we create it directly instead of reading it from the
		// manager. Once Coordinator.runner starts, it calls watchRuntimeComponents
		// in a helper goroutine, which subscribes directly to the runtime manager.
		// It then scans and logs any changes before forwarding the update
		// unmodified to this channel to merge with Coordinator.state. This is just
		// to keep the work of scanning and logging the component changes off the
		// main Coordinator goroutine.
		// Tests want to simulate a component state update can send directly to
		// this channel, as long as they aren't specifically testing the logging
		// behavior in watchRuntimeComponents.
		c.managerChans.runtimeManagerUpdate = make(chan runtime.ComponentComponentState)
		c.managerChans.runtimeManagerError = runtimeMgr.Errors()
	}
	if configMgr != nil {
		c.managerChans.configManagerUpdate = configMgr.Watch()
		c.managerChans.configManagerError = configMgr.Errors()
		c.managerChans.actionsError = configMgr.ActionErrors()
	}
	if varsMgr != nil {
		c.managerChans.varsManagerUpdate = varsMgr.Watch()
		c.managerChans.varsManagerError = varsMgr.Errors()
	}
	if upgradeMgr != nil && upgradeMgr.MarkerWatcher() != nil {
		c.managerChans.upgradeMarkerUpdate = upgradeMgr.MarkerWatcher().Watch()
		c.managerChans.upgradeMarkerErr = upgradeMgr.MarkerWatcher().Errors()
	}
	return c
}

// State returns the current state for the coordinator.
// Called by external goroutines.
func (c *Coordinator) State() State {
	return c.stateBroadcaster.Get()
}

func (c *Coordinator) RegisterMonitoringServer(s configReloader) {
	c.monitoringServerReloader = s
}

// StateSubscribe returns a channel that reports changes in Coordinator state.
//
// bufferLen specifies how many state changes should be queued in addition to
// the most recent one. If bufferLen is 0, reads on the channel always return
// the current state. Otherwise, multiple changes that occur between reads
// will accumulate up to bufferLen. If the most recent state has already been
// read, reads on the channel will block until the next state change.
//
// The returned channel always returns at least one value, and will keep
// returning changes until its context is cancelled or the Coordinator shuts
// down. After Coordinator shutdown, the channel will continue returning
// pending changes until the subscriber reads the final one, when the channel
// will be closed. On context cancel, the channel is closed immediately.
//
// This is safe to call from external goroutines, and subscriber behavior can
// never block Coordinator -- see the broadcaster package for detailed
// performance guarantees.
func (c *Coordinator) StateSubscribe(ctx context.Context, bufferLen int) chan State {
	return c.stateBroadcaster.Subscribe(ctx, bufferLen)
}

// Disabled for 8.8.0 release in order to limit the surface
// https://github.com/elastic/security-team/issues/6501

// // Protection returns the current agent protection configuration
// // This is needed to be able to access the protection configuration for actions validation
// func (c *Coordinator) Protection() protection.Config {
// 	c.mx.RLock()
// 	defer c.mx.RUnlock()
// 	return c.protection
// }

// // setProtection sets protection configuration
// func (c *Coordinator) setProtection(protectionConfig protection.Config) {
// 	c.mx.Lock()
// 	c.protection = protectionConfig
// 	c.mx.Unlock()
// }

// ReExec performs the re-execution.
// Called from external goroutines.
func (c *Coordinator) ReExec(callback reexec.ShutdownCallbackFn, argOverrides ...string) {
	// override the overall state to stopping until the re-execution is complete
	c.SetOverrideState(agentclient.Stopping, "Re-executing")
	c.reexecMgr.ReExec(callback, argOverrides...)
}

// Upgrade runs the upgrade process.
// Called from external goroutines.
func (c *Coordinator) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) error {
	// early check outside of upgrader before overriding the state
	if !c.upgradeMgr.Upgradeable() {
		return ErrNotUpgradable
	}

	// early check capabilities to ensure this upgrade actions is allowed
	if c.caps != nil {
		if !c.caps.AllowUpgrade(version, sourceURI) {
			return ErrNotUpgradable
		}
	}

	// A previous upgrade may be cancelled and needs some time to
	// run the callback to clear the state
	var err error
	for i := 0; i < 5; i++ {
		s := c.State()
		if s.State != agentclient.Upgrading {
			err = nil
			break
		}
		err = ErrUpgradeInProgress
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return err
	}

	// override the overall state to upgrading until the re-execution is complete
	c.SetOverrideState(agentclient.Upgrading, fmt.Sprintf("Upgrading to version %s", version))

	// initialize upgrade details
	actionID := ""
	if action != nil {
		actionID = action.ActionID
	}
	det := details.NewDetails(version, details.StateRequested, actionID)
	det.RegisterObserver(c.SetUpgradeDetails)
	det.RegisterObserver(c.logUpgradeDetails)

	cb, err := c.upgradeMgr.Upgrade(ctx, version, sourceURI, action, det, skipVerifyOverride, skipDefaultPgp, pgpBytes...)
	if err != nil {
		c.ClearOverrideState()
		det.Fail(err)
		return err
	}
	if cb != nil {
		det.SetState(details.StateRestarting)
		c.ReExec(cb)
	}
	return nil
}

func (c *Coordinator) logUpgradeDetails(details *details.Details) {
	c.logger.Infow("updated upgrade details", "upgrade_details", details)
}

// AckUpgrade is the method used on startup to ack a previously successful upgrade action.
// Called from external goroutines.
func (c *Coordinator) AckUpgrade(ctx context.Context, acker acker.Acker) error {
	return c.upgradeMgr.Ack(ctx, acker)
}

// PerformAction executes an action on a unit.
// Called from external goroutines.
func (c *Coordinator) PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
	return c.runtimeMgr.PerformAction(ctx, comp, unit, name, params)
}

// PerformDiagnostics executes the diagnostic action for the provided units. If no units are provided then
// it performs diagnostics for all current units.
// Called from external goroutines.
func (c *Coordinator) PerformDiagnostics(ctx context.Context, req ...runtime.ComponentUnitDiagnosticRequest) []runtime.ComponentUnitDiagnostic {
	return c.runtimeMgr.PerformDiagnostics(ctx, req...)
}

// PerformComponentDiagnostics executes the diagnostic action for the provided components.
func (c *Coordinator) PerformComponentDiagnostics(ctx context.Context, additionalMetrics []cproto.AdditionalDiagnosticRequest, req ...component.Component) ([]runtime.ComponentDiagnostic, error) {
	return c.runtimeMgr.PerformComponentDiagnostics(ctx, additionalMetrics, req...)
}

// SetLogLevel changes the entire log level for the running Elastic Agent.
// Called from external goroutines.
func (c *Coordinator) SetLogLevel(ctx context.Context, lvl logp.Level) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.logLevelCh <- lvl:
		// set global once the level change has been taken by the channel
		logger.SetLevel(lvl)
		return nil
	}
}

// watchRuntimeComponents listens for state updates from the runtime
// manager, logs them, and forwards them to CoordinatorState.
// Runs in its own goroutine created in Coordinator.Run.
func (c *Coordinator) watchRuntimeComponents(ctx context.Context) {
	state := make(map[string]runtime.ComponentState)

	var subChan <-chan runtime.ComponentComponentState
	// A real Coordinator will always have a runtime manager, but unit tests
	// may not initialize all managers -- in that case we leave subChan nil,
	// and just idle until Coordinator shuts down.
	if c.runtimeMgr != nil {
		subChan = c.runtimeMgr.SubscribeAll(ctx).Ch()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-subChan:
			oldState, ok := state[s.Component.ID]
			if !ok {
				componentLog := coordinatorComponentLog{
					ID:    s.Component.ID,
					State: s.State.State.String(),
				}
				logBasedOnState(c.logger, s.State.State, fmt.Sprintf("Spawned new component %s: %s", s.Component.ID, s.State.Message), "component", componentLog)
				for ui, us := range s.State.Units {
					unitLog := coordinatorUnitLog{
						ID:    ui.UnitID,
						Type:  ui.UnitType.String(),
						State: us.State.String(),
					}
					logBasedOnState(c.logger, us.State, fmt.Sprintf("Spawned new unit %s: %s", ui.UnitID, us.Message), "component", componentLog, "unit", unitLog)
				}
			} else {
				componentLog := coordinatorComponentLog{
					ID:    s.Component.ID,
					State: s.State.State.String(),
				}
				if oldState.State != s.State.State {
					cl := coordinatorComponentLog{
						ID:       s.Component.ID,
						State:    s.State.State.String(),
						OldState: oldState.State.String(),
					}
					logBasedOnState(c.logger, s.State.State, fmt.Sprintf("Component state changed %s (%s->%s): %s", s.Component.ID, oldState.State.String(), s.State.State.String(), s.State.Message), "component", cl)
				}
				for ui, us := range s.State.Units {
					oldUS, ok := oldState.Units[ui]
					if !ok {
						unitLog := coordinatorUnitLog{
							ID:    ui.UnitID,
							Type:  ui.UnitType.String(),
							State: us.State.String(),
						}
						logBasedOnState(c.logger, us.State, fmt.Sprintf("Spawned new unit %s: %s", ui.UnitID, us.Message), "component", componentLog, "unit", unitLog)
					} else if oldUS.State != us.State {
						unitLog := coordinatorUnitLog{
							ID:       ui.UnitID,
							Type:     ui.UnitType.String(),
							State:    us.State.String(),
							OldState: oldUS.State.String(),
						}
						logBasedOnState(c.logger, us.State, fmt.Sprintf("Unit state changed %s (%s->%s): %s", ui.UnitID, oldUS.State.String(), us.State.String(), us.Message), "component", componentLog, "unit", unitLog)
					}
				}
			}
			state[s.Component.ID] = s.State
			if s.State.State == client.UnitStateStopped {
				delete(state, s.Component.ID)
			}
			// Forward the final changes back to Coordinator, unless our context
			// has ended.
			select {
			case c.managerChans.runtimeManagerUpdate <- s:
			case <-ctx.Done():
				return
			}
		}
	}
}

// Run runs the Coordinator. Must be called on the Coordinator's main goroutine.
//
// The RuntimeManager, ConfigManager and VarsManager that is passed into NewCoordinator are also ran and lifecycle controlled by the Run.
//
// If any of the three managers fail, the Coordinator will shut down and
// Run will return an error.
func (c *Coordinator) Run(ctx context.Context) error {
	// log all changes in the state of the runtime and update the coordinator state
	watchCtx, watchCanceller := context.WithCancel(ctx)
	defer watchCanceller()
	go c.watchRuntimeComponents(watchCtx)

	// Close the state broadcaster on finish, but leave it running in the
	// background until all subscribers have read the final values or their
	// context ends, so test listeners and such can collect Coordinator's
	// shutdown state.
	defer close(c.stateBroadcaster.InputChan)

	// The usual state refresh happens in the main run loop in Coordinator.runner,
	// so before/after the runner call we need to trigger state change broadcasts
	// manually with refreshState.
	c.setCoordinatorState(agentclient.Starting, "Waiting for initial configuration and composable variables")
	c.refreshState()

	err := c.runner(ctx)

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		c.setCoordinatorState(agentclient.Stopped, "Requested to be stopped")
		c.setFleetState(agentclient.Stopped, "Requested to be stopped")
	} else {
		var message string
		if err != nil {
			message = fmt.Sprintf("Fatal coordinator error: %v", err.Error())
		} else {
			// runner should always return a non-nil error, but if it doesn't,
			// report it.
			message = "Coordinator terminated with unknown error (runner returned nil)"
		}
		c.setCoordinatorState(agentclient.Failed, message)
		c.setFleetState(agentclient.Stopped, message)
	}
	// Broadcast the final state in case anyone is still listening
	c.refreshState()

	return err
}

// DiagnosticHooks returns diagnostic hooks that can be connected to the control server to provide diagnostic
// information about the state of the Elastic Agent.
// Called by external goroutines.
func (c *Coordinator) DiagnosticHooks() diagnostics.Hooks {
	return diagnostics.Hooks{
		{
			Name:        "local-config",
			Filename:    "local-config.yaml",
			Description: "current local configuration of the running Elastic Agent",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				if c.cfg == nil {
					return []byte("error: failed no local configuration")
				}
				o, err := yaml.Marshal(c.cfg)
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				return o
			},
		},
		{
			Name:        "pre-config",
			Filename:    "pre-config.yaml",
			Description: "current pre-configuration of the running Elastic Agent before variable substitution",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				if c.ast == nil {
					return []byte("error: failed no configuration by the coordinator")
				}
				cfg, err := c.ast.Map()
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				o, err := yaml.Marshal(cfg)
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				return o
			},
		},
		{
			Name:        "variables",
			Filename:    "variables.yaml",
			Description: "current variable contexts of the running Elastic Agent",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				if c.vars == nil {
					return []byte("error: failed no variables by the coordinator")
				}
				vars := make([]map[string]interface{}, 0, len(c.vars))
				for _, v := range c.vars {
					m, err := v.Map()
					if err != nil {
						return []byte(fmt.Sprintf("error: %q", err))
					}
					vars = append(vars, m)
				}
				o, err := yaml.Marshal(struct {
					Variables []map[string]interface{} `yaml:"variables"`
				}{
					Variables: vars,
				})
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				return o
			},
		},
		{
			Name:        "computed-config",
			Filename:    "computed-config.yaml",
			Description: "current computed configuration of the running Elastic Agent after variable substitution",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				cfg := c.derivedConfig
				o, err := yaml.Marshal(cfg)
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				return o
			},
		},
		{
			Name:        "components-expected",
			Filename:    "components-expected.yaml",
			Description: "current expected components model of the running Elastic Agent",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				comps := c.componentModel
				o, err := yaml.Marshal(struct {
					Components []component.Component `yaml:"components"`
				}{
					Components: comps,
				})
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				return o
			},
		},
		{
			Name:        "components-actual",
			Filename:    "components-actual.yaml",
			Description: "actual components model of the running Elastic Agent",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				components := c.State().Components

				componentConfigs := make([]component.Component, len(components))
				for i := 0; i < len(components); i++ {
					componentConfigs[i] = components[i].Component
				}
				o, err := yaml.Marshal(struct {
					Components []component.Component `yaml:"components"`
				}{
					Components: componentConfigs,
				})
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				return o
			},
		},
		{
			Name:        "state",
			Filename:    "state.yaml",
			Description: "current state of running components by the Elastic Agent",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				type StateComponentOutput struct {
					ID    string                 `yaml:"id"`
					State runtime.ComponentState `yaml:"state"`
				}
				type StateHookOutput struct {
					State          agentclient.State      `yaml:"state"`
					Message        string                 `yaml:"message"`
					FleetState     agentclient.State      `yaml:"fleet_state"`
					FleetMessage   string                 `yaml:"fleet_message"`
					LogLevel       logp.Level             `yaml:"log_level"`
					Components     []StateComponentOutput `yaml:"components"`
					UpgradeDetails *details.Details       `yaml:"upgrade_details,omitempty"`
				}

				s := c.State()
				n := len(s.Components)
				compStates := make([]StateComponentOutput, n)
				for i := 0; i < n; i++ {
					compStates[i] = StateComponentOutput{
						ID:    s.Components[i].Component.ID,
						State: s.Components[i].State,
					}
				}
				output := StateHookOutput{
					State:          s.State,
					Message:        s.Message,
					FleetState:     s.FleetState,
					FleetMessage:   s.FleetMessage,
					LogLevel:       s.LogLevel,
					Components:     compStates,
					UpgradeDetails: s.UpgradeDetails,
				}
				o, err := yaml.Marshal(output)
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				return o
			},
		},
	}
}

// runner performs the actual work of running all the managers.
// Called on the main Coordinator goroutine, from Coordinator.Run.
//
// if one of the managers terminates the others are also stopped and then the whole runner returns
func (c *Coordinator) runner(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// We run nil checks before starting the various managers so that unit tests
	// only have to initialize / mock the specific components they're testing.
	// If a manager is nil, we prebuffer its return channel with nil also so
	// handleCoordinatorDone doesn't block waiting for its result on shutdown.
	// In a live agent, the manager fields are never nil.

	runtimeErrCh := make(chan error, 1)
	if c.runtimeMgr != nil {
		go func() {
			err := c.runtimeMgr.Run(ctx)
			cancel()
			runtimeErrCh <- err
		}()
	} else {
		runtimeErrCh <- nil
	}

	configErrCh := make(chan error, 1)
	if c.configMgr != nil {
		go func() {
			err := c.configMgr.Run(ctx)
			cancel()
			configErrCh <- err
		}()
	} else {
		configErrCh <- nil
	}

	varsErrCh := make(chan error, 1)
	if c.varsMgr != nil {
		go func() {
			err := c.varsMgr.Run(ctx)
			cancel()
			varsErrCh <- err
		}()
	} else {
		varsErrCh <- nil
	}

	upgradeMarkerWatcherErrCh := make(chan error, 1)
	if c.upgradeMgr != nil && c.upgradeMgr.MarkerWatcher() != nil {
		go func() {
			err := c.upgradeMgr.MarkerWatcher().Run(ctx)
			cancel()
			upgradeMarkerWatcherErrCh <- err
		}()
	} else {
		upgradeMarkerWatcherErrCh <- nil
	}

	// Keep looping until the context ends.
	for ctx.Err() == nil {
		c.runLoopIteration(ctx)
	}

	// If we got fatal errors from any of the managers, return them.
	// Otherwise, just return the context's closing error.
	err := collectManagerErrors(managerShutdownTimeout, varsErrCh, runtimeErrCh, configErrCh, upgradeMarkerWatcherErrCh)
	if err != nil {
		c.logger.Debugf("Manager errors on Coordinator shutdown: %v", err.Error())
		return err
	}
	return ctx.Err()
}

// runLoopIteration runs one iteration of the Coorinator's internal run
// loop in a standalone helper function to enable testing.
func (c *Coordinator) runLoopIteration(ctx context.Context) {
	select {
	case <-ctx.Done():
		return

	case runtimeErr := <-c.managerChans.runtimeManagerError:
		c.setRuntimeManagerError(runtimeErr)

	case configErr := <-c.managerChans.configManagerError:
		if c.isManaged {
			var wErr *WarningError
			if configErr == nil {
				c.setFleetState(agentclient.Healthy, "Connected")
			} else if errors.As(configErr, &wErr) {
				// we received a warning from Fleet, set state to degraded and the warning as state string
				c.setFleetState(agentclient.Degraded, wErr.Error())
			} else {
				c.setFleetState(agentclient.Failed, configErr.Error())
			}
		} else {
			// not managed gets sets as an overall error for the agent
			c.setConfigManagerError(configErr)
		}

	case actionsErr := <-c.managerChans.actionsError:
		c.setConfigManagerActionsError(actionsErr)

	case varsErr := <-c.managerChans.varsManagerError:
		c.setVarsManagerError(varsErr)

	case overrideState := <-c.overrideStateChan:
		c.setOverrideState(overrideState)

	case upgradeDetails := <-c.upgradeDetailsChan:
		c.setUpgradeDetails(upgradeDetails)

	case componentState := <-c.managerChans.runtimeManagerUpdate:
		// New component change reported by the runtime manager via
		// Coordinator.watchRuntimeComponents(), merge it with the
		// Coordinator state.
		c.applyComponentState(componentState)

	case change := <-c.managerChans.configManagerUpdate:
		if err := c.processConfig(ctx, change.Config()); err != nil {
			c.logger.Errorf("applying new policy: %s", err.Error())
			change.Fail(err)
		} else {
			if err := change.Ack(); err != nil {
				err = fmt.Errorf("failed to ack configuration change: %w", err)
				// Workaround: setConfigManagerError is usually used by the config
				// manager to report failed ACKs / etc when communicating with Fleet.
				// We need to report a failed ACK here, but the policy change has
				// already been successfully applied so we don't want to report it as
				// a general Coordinator or policy failure.
				// This arises uniquely here because this is the only case where an
				// action is responsible for reporting the failure of its own ACK
				// call. The "correct" fix is to make this Ack() call unfailable
				// and handle ACK retries and reporting in the config manager like
				// with other action types -- this error would then end up invoking
				// setConfigManagerError "organically" via the config manager's
				// reporting channel. In the meantime, we do it manually.
				c.setConfigManagerError(err)
				c.logger.Errorf("%s", err.Error())
			}
		}

	case vars := <-c.managerChans.varsManagerUpdate:
		if ctx.Err() == nil {
			c.processVars(ctx, vars)
		}

	case ll := <-c.logLevelCh:
		if ctx.Err() == nil {
			c.processLogLevel(ctx, ll)
		}

	case upgradeMarker := <-c.managerChans.upgradeMarkerUpdate:
		if ctx.Err() == nil {
			c.setUpgradeDetails(upgradeMarker.Details)
		}
	}

	// At the end of each iteration, if we made any changes to the state,
	// collect them and send them to stateBroadcaster.
	if c.stateNeedsRefresh {
		c.refreshState()
	}
}

// Always called on the main Coordinator goroutine.
func (c *Coordinator) processConfig(ctx context.Context, cfg *config.Config) (err error) {
	span, ctx := apm.StartSpan(ctx, "config", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	err = c.generateAST(cfg)
	c.setConfigError(err)
	if err != nil {
		return err
	}

	// Disabled for 8.8.0 release in order to limit the surface
	// https://github.com/elastic/security-team/issues/6501

	// c.setProtection(protectionConfig)

	if c.vars != nil {
		return c.refreshComponentModel(ctx)
	}
	return nil
}

// Generate the AST for a new incoming configuration and, if successful,
// assign it to the Coordinator's ast field.
func (c *Coordinator) generateAST(cfg *config.Config) (err error) {
	defer func() {
		// Update configErr, which stores the results of the most recent policy
		// update and is merged into the Coordinator state in
		// generateReportableState.
		c.setConfigError(err)
	}()

	if err = info.InjectAgentConfig(cfg); err != nil {
		return err
	}

	// perform and verify ast translation
	m, err := cfg.ToMapStr()
	if err != nil {
		return fmt.Errorf("could not create the map from the configuration: %w", err)
	}

	// Disabled for 8.8.0 release in order to limit the surface
	// https://github.com/elastic/security-team/issues/6501
	// protectionConfig, err := protection.GetAgentProtectionConfig(m)
	// if err != nil && !errors.Is(err, protection.ErrNotFound) {
	// 	return fmt.Errorf("could not read the agent protection configuration: %w", err)
	// }

	rawAst, err := transpiler.NewAST(m)
	if err != nil {
		return fmt.Errorf("could not create the AST from the configuration: %w", err)
	}

	// applying updated agent process limits
	if err := limits.Apply(cfg); err != nil {
		return fmt.Errorf("could not update limits config: %w", err)
	}

	if err := features.Apply(cfg); err != nil {
		return fmt.Errorf("could not update feature flags config: %w", err)
	}

	// Check the upgrade and monitoring managers before updating them. Real
	// Coordinators always have them, but not all tests do, and in that case
	// we should skip the Reload call rather than segfault.

	if c.upgradeMgr != nil {
		if err := c.upgradeMgr.Reload(cfg); err != nil {
			return fmt.Errorf("failed to reload upgrade manager configuration: %w", err)
		}
	}

	if c.monitorMgr != nil {
		if err := c.monitorMgr.Reload(cfg); err != nil {
			return fmt.Errorf("failed to reload monitor manager configuration: %w", err)
		}
	}

	if c.monitoringServerReloader != nil {
		if err := c.monitoringServerReloader.Reload(cfg); err != nil {
			return fmt.Errorf("failed to reload monitor manager configuration: %w", err)
		}
	}

	c.ast = rawAst
	return nil
}

// processVars updates the transpiler vars in the Coordinator.
// Called on the main Coordinator goroutine.
func (c *Coordinator) processVars(ctx context.Context, vars []*transpiler.Vars) {
	c.vars = vars
	err := c.refreshComponentModel(ctx)
	if err != nil {
		c.logger.Errorf("updating Coordinator variables: %s", err.Error())
	}
}

// Called on the main Coordinator goroutine.
func (c *Coordinator) processLogLevel(ctx context.Context, ll logp.Level) {
	c.setLogLevel(ll)
	err := c.refreshComponentModel(ctx)
	if err != nil {
		c.logger.Errorf("updating log level: %s", err.Error())
	}
}

// Regenerate the component model based on the current vars and AST, then
// forward the result to the runtime manager.
// Always called on the main Coordinator goroutine.
func (c *Coordinator) refreshComponentModel(ctx context.Context) (err error) {
	if c.ast == nil || c.vars == nil {
		// Nothing to process yet
		return nil
	}

	span, ctx := apm.StartSpan(ctx, "refreshComponentModel", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	// regenerate the component model
	err = c.generateComponentModel()
	if err != nil {
		return fmt.Errorf("generating component model: %w", err)
	}

	signed, err := component.SignedFromPolicy(c.derivedConfig)
	if err != nil {
		if !errors.Is(err, component.ErrNotFound) {
			c.logger.Errorf("Failed to parse \"signed\" properties: %v", err)
			return err
		}

		// Some "signed" properties are not found, continue.
		c.logger.Debugf("Continue with missing \"signed\" properties: %v", err)
	}

	model := component.Model{
		Components: c.componentModel,
		Signed:     signed,
	}

	c.logger.Info("Updating running component model")
	c.logger.With("components", model.Components).Debug("Updating running component model")
	err = c.runtimeMgr.Update(model)
	c.setRuntimeUpdateError(err)
	if err != nil {
		return fmt.Errorf("updating runtime: %w", err)
	}
	c.setCoordinatorState(agentclient.Healthy, "Running")
	return nil
}

// generateComponentModel regenerates the configuration tree and
// components from the current AST and vars and returns the result.
// Called from both the main Coordinator goroutine and from external
// goroutines via diagnostics hooks.
func (c *Coordinator) generateComponentModel() (err error) {
	defer func() {
		// Update componentGenErr with the results.
		c.setComponentGenError(err)
	}()

	ast := c.ast.Clone()
	inputs, ok := transpiler.Lookup(ast, "inputs")
	if ok {
		renderedInputs, err := transpiler.RenderInputs(inputs, c.vars)
		if err != nil {
			return fmt.Errorf("rendering inputs failed: %w", err)
		}
		err = transpiler.Insert(ast, renderedInputs, "inputs")
		if err != nil {
			return fmt.Errorf("inserting rendered inputs failed: %w", err)
		}
	}

	cfg, err := ast.Map()
	if err != nil {
		return fmt.Errorf("failed to convert ast to map[string]interface{}: %w", err)
	}
	var configInjector component.GenerateMonitoringCfgFn
	if c.monitorMgr != nil && c.monitorMgr.Enabled() {
		configInjector = c.monitorMgr.MonitoringConfig
	}

	comps, err := c.specs.ToComponents(
		cfg,
		configInjector,
		c.state.LogLevel,
		c.agentInfo,
	)
	if err != nil {
		return fmt.Errorf("failed to render components: %w", err)
	}

	// Filter any disallowed inputs/outputs from the components
	comps = c.filterByCapabilities(comps)

	for _, modifier := range c.modifiers {
		comps, err = modifier(comps, cfg)
		if err != nil {
			return fmt.Errorf("failed to modify components: %w", err)
		}
	}

	// If we made it this far, update our internal derived values and
	// return with no error
	c.derivedConfig = cfg
	c.componentModel = comps
	return nil
}

// Filter any inputs and outputs in the generated component model
// based on whether they're excluded by the capabilities config
func (c *Coordinator) filterByCapabilities(comps []component.Component) []component.Component {
	if c.caps == nil {
		// No active filters, return unchanged
		return comps
	}
	result := []component.Component{}
	for _, component := range comps {
		// If this is an input component (not a shipper), make sure its type is allowed
		if component.InputSpec != nil && !c.caps.AllowInput(component.InputType) {
			c.logger.Info("Component '%v' with input type '%v' filtered by capabilities.yml", component.InputType)
			continue
		}
		if !c.caps.AllowOutput(component.OutputType) {
			c.logger.Info("Component '%v' with output type '%v' filtered by capabilities.yml", component.ID, component.OutputType)
			continue
		}
		result = append(result, component)
	}
	return result
}

// collectManagerErrors listens on the shutdown channels for the
// runtime, config, and vars managers, and waits for up to
// the specified timeout for them to report their final status.
// It returns any resulting errors as a multierror, or nil if no errors
// were reported.
// Called on the main Coordinator goroutine.
func collectManagerErrors(timeout time.Duration, varsErrCh, runtimeErrCh, configErrCh, upgradeMarkerWatchErrCh chan error) error {
	var runtimeErr, configErr, varsErr, upgradeMarkerErr error
	var returnedRuntime, returnedConfig, returnedVars, returnedUpgradeMarker bool

	// in case other components are locked up, let us time out
	timeoutWait := time.NewTimer(timeout)
	defer timeoutWait.Stop()

	/*
		Wait for all managers to gently shut down. All managers send
		an error status on their termination channel after their Run method
		returns.
		Logic:
		If all three manager channels return a value, or close, we're done.
		If any errors are non-nil (and not just context.Canceled), collect and
		return them with multierror.
		Otherwise, return nil.
	*/

	// combinedErr will store any reported errors as well as timeout errors
	// for unresponsive managers.
	var combinedErr error

waitLoop:
	for !returnedRuntime || !returnedConfig || !returnedVars || !returnedUpgradeMarker {
		select {
		case runtimeErr = <-runtimeErrCh:
			returnedRuntime = true
		case configErr = <-configErrCh:
			returnedConfig = true
		case varsErr = <-varsErrCh:
			returnedVars = true
		case upgradeMarkerErr = <-upgradeMarkerWatchErrCh:
			returnedUpgradeMarker = true
		case <-timeoutWait.C:
			var timeouts []string
			if !returnedRuntime {
				timeouts = []string{"no response from runtime manager"}
			}
			if !returnedConfig {
				timeouts = append(timeouts, "no response from config manager")
			}
			if !returnedVars {
				timeouts = append(timeouts, "no response from vars manager")
			}
			if !returnedUpgradeMarker {
				timeouts = append(timeouts, "no response from upgradeMarkerWatcher component")
			}
			timeoutStr := strings.Join(timeouts, ", ")
			combinedErr = multierror.Append(combinedErr, fmt.Errorf("timeout while waiting for managers to shut down: %v", timeoutStr))
			break waitLoop
		}
	}
	if runtimeErr != nil && !errors.Is(runtimeErr, context.Canceled) {
		combinedErr = multierror.Append(combinedErr, fmt.Errorf("runtime manager: %w", runtimeErr))
	}
	if configErr != nil && !errors.Is(configErr, context.Canceled) {
		combinedErr = multierror.Append(combinedErr, fmt.Errorf("config manager: %w", configErr))
	}
	if varsErr != nil && !errors.Is(varsErr, context.Canceled) {
		combinedErr = multierror.Append(combinedErr, fmt.Errorf("vars manager: %w", varsErr))
	}
	if upgradeMarkerErr != nil && !errors.Is(varsErr, context.Canceled) {
		combinedErr = multierror.Append(combinedErr, fmt.Errorf("upgrade marker watcher: %w", upgradeMarkerErr))
	}
	return combinedErr
}

type coordinatorComponentLog struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	OldState string `json:"old_state,omitempty"`
}

type coordinatorUnitLog struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	State    string `json:"state"`
	OldState string `json:"old_state,omitempty"`
}

func logBasedOnState(l *logger.Logger, state client.UnitState, msg string, args ...interface{}) {
	// Skipping one more stack frame in order to have correct file line set in the logger output while using this wrapper function
	l = logger.AddCallerSkip(l, 1)

	switch state {
	case client.UnitStateStarting:
		l.With(args...).Info(msg)
	case client.UnitStateConfiguring:
		l.With(args...).Info(msg)
	case client.UnitStateDegraded:
		l.With(args...).Warn(msg)
	case client.UnitStateHealthy:
		l.With(args...).Info(msg)
	case client.UnitStateFailed:
		l.With(args...).Error(msg)
	case client.UnitStateStopping:
		l.With(args...).Info(msg)
	case client.UnitStateStopped:
		l.With(args...).Info(msg)
	default:
		l.With(args...).Info(msg)
	}
}
