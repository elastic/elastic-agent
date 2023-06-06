// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"

	"go.elastic.co/apm"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/state"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
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
	Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, skipVerifyOverride bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error)

	// Ack is used on startup to check if the agent has upgraded and needs to send an ack for the action
	Ack(ctx context.Context, acker acker.Acker) error
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
	Update([]component.Component) error

	// State returns the current components model state.
	State() []runtime.ComponentComponentState

	// PerformAction executes an action on a unit.
	PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error)

	// SubscribeAll provides an interface to watch for changes in all components.
	SubscribeAll(context.Context) *runtime.SubscriptionAll

	// PerformDiagnostics executes the diagnostic action for the provided units. If no units are provided then
	// it performs diagnostics for all current units.
	PerformDiagnostics(context.Context, ...runtime.ComponentUnitDiagnosticRequest) []runtime.ComponentUnitDiagnostic
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

// CoordinatorShutdownTimeout is how long the coordinator will wait during shutdown to receive a "clean" shutdown from other components
var CoordinatorShutdownTimeout = time.Second * 5

// Coordinator manages the entire state of the Elastic Agent.
//
// All configuration changes, update variables, and upgrade actions are managed and controlled by the coordinator.
type Coordinator struct {
	logger    *logger.Logger
	agentInfo *info.AgentInfo
	isManaged bool

	cfg   *configuration.Configuration
	specs component.RuntimeSpecs

	logLevelCh chan logp.Level
	logLevel   logp.Level

	reexecMgr  ReExecManager
	upgradeMgr UpgradeManager
	monitorMgr MonitorManager

	runtimeMgr RuntimeManager
	configMgr  ConfigManager
	varsMgr    VarsManager

	caps      capabilities.Capability
	modifiers []ComponentsModifier

	state  *state.CoordinatorState
	config *config.Config
	ast    *transpiler.AST
	vars   []*transpiler.Vars

	// Disabled for 8.8.0 release in order to limit the surface
	// https://github.com/elastic/security-team/issues/6501

	// mx         sync.RWMutex
	// protection protection.Config
}

// ErrFatalCoordinator is returned when a coordinator sub-component returns an error, as opposed to a simple context-cancelled.
var ErrFatalCoordinator = errors.New("fatal error in coordinator")

// New creates a new coordinator.
func New(logger *logger.Logger, cfg *configuration.Configuration, logLevel logp.Level, agentInfo *info.AgentInfo, specs component.RuntimeSpecs, reexecMgr ReExecManager, upgradeMgr UpgradeManager, runtimeMgr RuntimeManager, configMgr ConfigManager, varsMgr VarsManager, caps capabilities.Capability, monitorMgr MonitorManager, isManaged bool, modifiers ...ComponentsModifier) *Coordinator {
	var fleetState cproto.State
	var fleetMessage string
	if !isManaged {
		// default enum value is STARTING which is confusing for standalone
		fleetState = agentclient.Stopped
		fleetMessage = "Not enrolled into Fleet"
	}
	return &Coordinator{
		logger:     logger,
		cfg:        cfg,
		agentInfo:  agentInfo,
		isManaged:  isManaged,
		specs:      specs,
		logLevelCh: make(chan logp.Level),
		reexecMgr:  reexecMgr,
		upgradeMgr: upgradeMgr,
		monitorMgr: monitorMgr,
		runtimeMgr: runtimeMgr,
		configMgr:  configMgr,
		varsMgr:    varsMgr,
		caps:       caps,
		modifiers:  modifiers,
		state:      state.NewCoordinatorState(agentclient.Starting, "Starting", fleetState, fleetMessage, logLevel),
	}
}

// State returns the current state for the coordinator.
// Called by external goroutines.
func (c *Coordinator) State() state.State {
	return c.state.State()
}

// StateSubscribe subscribes to changes in the coordinator state.
// Called by external goroutines (currently just from the StateWatch RPC).
//
// This provides the current state at the time of first subscription. Cancelling the context
// results in the subscription being unsubscribed.
//
// Note: Not reading from a subscription channel will cause the Coordinator to block.
func (c *Coordinator) StateSubscribe(ctx context.Context) *state.StateSubscription {
	return c.state.Subscribe(ctx)
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
	c.state.SetOverrideState(agentclient.Stopping, "Re-executing")
	c.reexecMgr.ReExec(callback, argOverrides...)
}

// Upgrade runs the upgrade process.
// Called from external goroutines.
func (c *Coordinator) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, skipVerifyOverride bool, pgpBytes ...string) error {
	// early check outside of upgrader before overridding the state
	if !c.upgradeMgr.Upgradeable() {
		return ErrNotUpgradable
	}

	// early check capabilities to ensure this upgrade actions is allowed
	if c.caps != nil {
		if _, err := c.caps.Apply(map[string]interface{}{
			"version":   version,
			"sourceURI": sourceURI,
		}); errors.Is(err, capabilities.ErrBlocked) {
			return ErrNotUpgradable
		}
	}

	// A previous upgrade may be cancelled and needs some time to
	// run the callback to clear the state
	var err error
	for i := 0; i < 5; i++ {
		s := c.state.State()
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
	c.state.SetOverrideState(agentclient.Upgrading, fmt.Sprintf("Upgrading to version %s", version))
	cb, err := c.upgradeMgr.Upgrade(ctx, version, sourceURI, action, skipVerifyOverride, pgpBytes...)
	if err != nil {
		c.state.ClearOverrideState()
		return err
	}
	if cb != nil {
		c.ReExec(cb)
	}
	return nil
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

	sub := c.runtimeMgr.SubscribeAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-sub.Ch():
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
			c.state.UpdateComponentState(s)
		}
	}
}

// Run runs the Coordinator. Must be called on the Coordinator's main goroutine.
//
// The RuntimeManager, ConfigManager and VarsManager that is passed into NewCoordinator are also ran and lifecycle controlled by the Run.
//
// In the case that either of the above managers fail, they will all be restarted unless the context was explicitly cancelled or timed out.
func (c *Coordinator) Run(ctx context.Context) error {
	// log all changes in the state of the runtime and update the coordinator state
	// TODO: nothing cancels this listener goroutine when Run returns.
        watchCtx, watchCanceller := context.WithCancel(ctx)
        defer watchCanceller()
	go c.watchRuntimeComponents(watchCtx)

	for {
		c.state.UpdateState(state.WithState(agentclient.Starting, "Waiting for initial configuration and composable variables"))
		err := c.runner(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				c.state.UpdateState(state.WithState(agentclient.Stopped, "Requested to be stopped"), state.WithFleetState(agentclient.Stopped, "Requested to be stopped"))
				// do not restart
				return err
			}
			if errors.Is(err, ErrFatalCoordinator) {
				c.state.UpdateState(state.WithState(agentclient.Failed, "Fatal coordinator error"), state.WithFleetState(agentclient.Stopped, "Fatal coordinator error"))
				return err
			}
		}
		c.state.UpdateState(state.WithState(agentclient.Failed, fmt.Sprintf("Coordinator failed and will be restarted: %s", err)))
		c.logger.Errorf("coordinator failed and will be restarted: %s", err)
	}
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
				if c.ast == nil || c.vars == nil {
					return []byte("error: failed no configuration or variables received by the coordinator")
				}
				cfg, _, err := c.compute()
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
			Name:        "components-expected",
			Filename:    "components-expected.yaml",
			Description: "current expected components model of the running Elastic Agent",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				if c.ast == nil || c.vars == nil {
					return []byte("error: failed no configuration or variables received by the coordinator")
				}
				_, comps, err := c.compute()
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
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
					State        agentclient.State      `yaml:"state"`
					Message      string                 `yaml:"message"`
					FleetState   agentclient.State      `yaml:"fleet_state"`
					FleetMessage string                 `yaml:"fleet_message"`
					LogLevel     logp.Level             `yaml:"log_level"`
					Components   []StateComponentOutput `yaml:"components"`
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
					State:        s.State,
					Message:      s.Message,
					FleetState:   s.FleetState,
					FleetMessage: s.FleetMessage,
					LogLevel:     s.LogLevel,
					Components:   compStates,
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
// if one of the managers fails the others are also stopped and then the whole runner returns
func (c *Coordinator) runner(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	runtimeWatcher := c.runtimeMgr
	runtimeRun := make(chan bool)
	runtimeErrCh := make(chan error)
	go func(manager Runner) {
		err := manager.Run(ctx)
		close(runtimeRun)
		runtimeErrCh <- err
	}(runtimeWatcher)

	configWatcher := c.configMgr
	configRun := make(chan bool)
	configErrCh := make(chan error)
	go func(manager Runner) {
		err := manager.Run(ctx)
		close(configRun)
		configErrCh <- err
	}(configWatcher)

	varsWatcher := c.varsMgr
	varsRun := make(chan bool)
	varsErrCh := make(chan error)
	go func(manager Runner) {
		err := manager.Run(ctx)
		close(varsRun)
		varsErrCh <- err
	}(varsWatcher)

	for {
		select {
		case <-ctx.Done():
			return c.handleCoordinatorDone(ctx, varsErrCh, runtimeErrCh, configErrCh)
		case <-runtimeRun:
			if ctx.Err() == nil {
				cancel()
			}
		case <-configRun:
			if ctx.Err() == nil {
				cancel()
			}
		case <-varsRun:
			if ctx.Err() == nil {
				cancel()
			}
		case runtimeErr := <-c.runtimeMgr.Errors():
			c.state.SetRuntimeManagerError(runtimeErr)
		case configErr := <-c.configMgr.Errors():
			if c.isManaged {
				if configErr == nil {
					c.state.UpdateState(state.WithFleetState(agentclient.Healthy, "Connected"))
				} else {
					c.state.UpdateState(state.WithFleetState(agentclient.Failed, configErr.Error()))
				}
			} else {
				// not managed gets sets as an overall error for the agent
				c.state.SetConfigManagerError(configErr)
			}
		case actionsErr := <-c.configMgr.ActionErrors():
			c.state.SetConfigManagerActionsError(actionsErr)
		case varsErr := <-c.varsMgr.Errors():
			c.state.SetVarsManagerError(varsErr)
		case change := <-configWatcher.Watch():
			if ctx.Err() == nil {
				if err := c.processConfig(ctx, change.Config()); err != nil {
					c.state.UpdateState(state.WithState(agentclient.Failed, err.Error()))
					c.logger.Errorf("%s", err)
					change.Fail(err)
				} else {
					if err := change.Ack(); err != nil {
						err = fmt.Errorf("failed to ack configuration change: %w", err)
						c.state.UpdateState(state.WithState(agentclient.Failed, err.Error()))
						c.logger.Errorf("%s", err)
					}
				}
			}
		case vars := <-varsWatcher.Watch():
			if ctx.Err() == nil {
				if err := c.processVars(ctx, vars); err != nil {
					c.state.UpdateState(state.WithState(agentclient.Failed, err.Error()))
					c.logger.Errorf("%s", err)
				}
			}
		case ll := <-c.logLevelCh:
			if ctx.Err() == nil {
				if err := c.processLogLevel(ctx, ll); err != nil {
					c.state.UpdateState(state.WithState(agentclient.Failed, err.Error()))
					c.logger.Errorf("%s", err)
				}
			}
		}
	}
}

// Always called on the main Coordinator goroutine.
func (c *Coordinator) processConfig(ctx context.Context, cfg *config.Config) (err error) {
	span, ctx := apm.StartSpan(ctx, "config", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	if err := info.InjectAgentConfig(cfg); err != nil {
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

	if c.caps != nil {
		var ok bool
		updatedAst, err := c.caps.Apply(rawAst)
		if err != nil {
			return fmt.Errorf("failed to apply capabilities: %w", err)
		}

		rawAst, ok = updatedAst.(*transpiler.AST)
		if !ok {
			return fmt.Errorf("failed to transform object returned from capabilities to AST: %w", err)
		}
	}

	if err := features.Apply(cfg); err != nil {
		return fmt.Errorf("could not update feature flags config: %w", err)
	}

	if err := c.upgradeMgr.Reload(cfg); err != nil {
		return fmt.Errorf("failed to reload upgrade manager configuration: %w", err)
	}

	if err := c.monitorMgr.Reload(cfg); err != nil {
		return fmt.Errorf("failed to reload upgrade manager configuration: %w", err)
	}

	c.config = cfg
	c.ast = rawAst

	// Disabled for 8.8.0 release in order to limit the surface
	// https://github.com/elastic/security-team/issues/6501

	// c.setProtection(protectionConfig)

	if c.vars != nil {
		return c.process(ctx)
	}
	return nil
}

// processVars updates the transpiler vars in the Coordinator.
// Called on the main Coordinator goroutine.
func (c *Coordinator) processVars(ctx context.Context, vars []*transpiler.Vars) (err error) {
	span, ctx := apm.StartSpan(ctx, "vars", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	c.vars = vars

	if c.ast != nil {
		return c.process(ctx)
	}
	return nil
}

// Called on the main Coordinator goroutine.
func (c *Coordinator) processLogLevel(ctx context.Context, ll logp.Level) (err error) {
	span, ctx := apm.StartSpan(ctx, "log_level", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	c.logLevel = ll
	c.state.UpdateState(state.WithLogLevel(ll))

	if c.ast != nil && c.vars != nil {
		return c.process(ctx)
	}
	return nil
}

// Always called on the main Coordinator goroutine.
func (c *Coordinator) process(ctx context.Context) (err error) {
	span, ctx := apm.StartSpan(ctx, "process", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	_, comps, err := c.compute()
	if err != nil {
		return err
	}

	c.logger.Info("Updating running component model")
	c.logger.With("components", comps).Debug("Updating running component model")
	err = c.runtimeMgr.Update(comps)
	if err != nil {
		return err
	}
	c.state.UpdateState(state.WithState(agentclient.Healthy, "Running"))
	return nil
}

// Called from both the main Coordinator goroutine and from external
// goroutines via diagnostics hooks.
func (c *Coordinator) compute() (map[string]interface{}, []component.Component, error) {
	ast := c.ast.Clone()
	inputs, ok := transpiler.Lookup(ast, "inputs")
	if ok {
		renderedInputs, err := transpiler.RenderInputs(inputs, c.vars)
		if err != nil {
			return nil, nil, fmt.Errorf("rendering inputs failed: %w", err)
		}
		err = transpiler.Insert(ast, renderedInputs, "inputs")
		if err != nil {
			return nil, nil, fmt.Errorf("inserting rendered inputs failed: %w", err)
		}
	}

	cfg, err := ast.Map()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert ast to map[string]interface{}: %w", err)
	}

	var configInjector component.GenerateMonitoringCfgFn
	if c.monitorMgr.Enabled() {
		configInjector = c.monitorMgr.MonitoringConfig
	}

	comps, err := c.specs.ToComponents(
		cfg,
		configInjector,
		c.State().LogLevel,
		c.agentInfo,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to render components: %w", err)
	}

	for _, modifier := range c.modifiers {
		comps, err = modifier(comps, cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to modify components: %w", err)
		}
	}

	return cfg, comps, nil
}

// handleCoordinatorDone is called when the Coordinator's context is
// finished. It waits for the runtime, config, and vars managers to finish,
// and collects their return values into an error if any of them returned
// for a reason other than context.Canceled.
// Called on the main Coordinator goroutine.
func (c *Coordinator) handleCoordinatorDone(ctx context.Context, varsErrCh, runtimeErrCh, configErrCh chan error) error {
	var runtimeErr error
	var configErr error
	var varsErr error
	// in case other components are locked up, let us time out
	timeoutWait := time.NewTimer(CoordinatorShutdownTimeout)
	defer timeoutWait.Stop()
	var returnedRuntime, returnedConfig, returnedVars bool
	/*
		Wait for all subcomponents to gently shut down.
		Logic:
		If all three subcomponent channels return an error, or close,
		Assume shutdown is complete.
		If there's a non-nil error, return it as an ErrFatalCoordinator,
		If there's no errors from the channels, pass on the underlying context error
	*/

waitLoop:
	for !returnedRuntime || !returnedConfig || !returnedVars {
		select {
		case runtimeErr = <-runtimeErrCh:
			returnedRuntime = true
		case configErr = <-configErrCh:
			returnedConfig = true
		case varsErr = <-varsErrCh:
			returnedVars = true
		case <-timeoutWait.C:
			var timeouts []string
			if !returnedRuntime {
				timeouts = []string{"no response from runtime component"}
			}
			if !returnedConfig {
				timeouts = append(timeouts, "no response from configWatcher component")
			}
			if !returnedVars {
				timeouts = append(timeouts, "no response from varsWatcher component")
			}
			c.logger.Debugf("timeout while waiting for other components to shut down: %v", timeouts)
			break waitLoop
		}
	}
	// try not to lose any errors
	var combinedErr error
	if runtimeErr != nil && !errors.Is(runtimeErr, context.Canceled) {
		c.logger.Debugf("runtime component shut down with error: %s", runtimeErr)
		combinedErr = multierror.Append(combinedErr, fmt.Errorf("runtime Manager: %w", runtimeErr))
	}
	if configErr != nil && !errors.Is(configErr, context.Canceled) {
		c.logger.Debugf("config manager shut down with error: %s", configErr)
		combinedErr = multierror.Append(combinedErr, fmt.Errorf("config Manager: %w", configErr))
	}
	if varsErr != nil && !errors.Is(varsErr, context.Canceled) {
		c.logger.Debugf("varsWatcher shut down with error: %s", varsErr)
		combinedErr = multierror.Append(combinedErr, fmt.Errorf("vars Watcher: %w", varsErr))
	}
	if combinedErr != nil {
		return fmt.Errorf("%w: %s", ErrFatalCoordinator, combinedErr.Error()) //nolint:errorlint //errors.Is() won't work if we pass through the combined errors with %w
	}
	// if there's no component errors, continue to pass along the context error
	return ctx.Err()
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
