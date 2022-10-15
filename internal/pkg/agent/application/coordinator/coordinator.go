// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"

	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	agentclient "github.com/elastic/elastic-agent/internal/pkg/agent/control/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var (
	// ErrNotUpgradable error is returned when upgrade cannot be performed.
	ErrNotUpgradable = errors.New(
		"cannot be upgraded; must be installed with install sub-command and " +
			"running under control of the systems supervisor")
)

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
	Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade) (_ reexec.ShutdownCallbackFn, err error)

	// Ack is used on startup to check if the agent has upgraded and needs to send an ack for the action
	Ack(ctx context.Context, acker acker.Acker) error
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
	PerformAction(ctx context.Context, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error)

	// SubscribeAll provides an interface to watch for changes in all components.
	SubscribeAll(context.Context) *runtime.SubscriptionAll

	// PerformDiagnostics executes the diagnostic action for the provided units. If no units are provided then
	// it performs diagnostics for all current units.
	PerformDiagnostics(context.Context, ...component.Unit) []runtime.ComponentUnitDiagnostic
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
type ErrorReporter interface {
}

// ConfigManager provides an interface to run and watch for configuration changes.
type ConfigManager interface {
	Runner

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

// State provides the current state of the coordinator along with all the current states of components and units.
type State struct {
	State      agentclient.State                 `yaml:"state"`
	Message    string                            `yaml:"message"`
	Components []runtime.ComponentComponentState `yaml:"components"`
}

// StateFetcher provides an interface to fetch the current state of the coordinator.
type StateFetcher interface {
	// State returns the current state of the coordinator.
	State() State
}

// Coordinator manages the entire state of the Elastic Agent.
//
// All configuration changes, update variables, and upgrade actions are managed and controlled by the coordinator.
type Coordinator struct {
	logger    *logger.Logger
	agentInfo *info.AgentInfo

	specs component.RuntimeSpecs

	reexecMgr  ReExecManager
	upgradeMgr UpgradeManager

	runtimeMgr    RuntimeManager
	runtimeMgrErr error
	configMgr     ConfigManager
	configMgrErr  error
	varsMgr       VarsManager
	varsMgrErr    error

	caps      capabilities.Capability
	modifiers []ComponentsModifier

	state coordinatorState
}

// New creates a new coordinator.
func New(logger *logger.Logger, agentInfo *info.AgentInfo, specs component.RuntimeSpecs, reexecMgr ReExecManager, upgradeMgr UpgradeManager, runtimeMgr RuntimeManager, configMgr ConfigManager, varsMgr VarsManager, caps capabilities.Capability, modifiers ...ComponentsModifier) *Coordinator {
	return &Coordinator{
		logger:     logger,
		agentInfo:  agentInfo,
		specs:      specs,
		reexecMgr:  reexecMgr,
		upgradeMgr: upgradeMgr,
		runtimeMgr: runtimeMgr,
		configMgr:  configMgr,
		varsMgr:    varsMgr,
		caps:       caps,
		modifiers:  modifiers,
		state: coordinatorState{
			state: agentclient.Starting,
		},
	}
}

// State returns the current state for the coordinator.
func (c *Coordinator) State() (s State) {
	s.State = c.state.state
	s.Message = c.state.message
	s.Components = c.runtimeMgr.State()
	if c.state.overrideState != nil {
		// state has been overridden due to an action that is occurring
		s.State = c.state.overrideState.state
		s.Message = c.state.overrideState.message
	} else if s.State == agentclient.Healthy {
		// if any of the managers are reporting an error then something is wrong
		// or
		// coordinator overall is reported is healthy; in the case any component or unit is not healthy then we report
		// as degraded because we are not fully healthy
		if c.runtimeMgrErr != nil {
			s.State = agentclient.Failed
			s.Message = c.runtimeMgrErr.Error()
		} else if c.configMgrErr != nil {
			s.State = agentclient.Failed
			s.Message = c.configMgrErr.Error()
		} else if c.varsMgrErr != nil {
			s.State = agentclient.Failed
			s.Message = c.varsMgrErr.Error()
		} else if hasState(s.Components, client.UnitStateFailed) {
			s.State = agentclient.Degraded
			s.Message = "1 or more components/units in a failed state"
		} else if hasState(s.Components, client.UnitStateDegraded) {
			s.State = agentclient.Degraded
			s.Message = "1 or more components/units in a degraded state"
		}
	}
	return s
}

// ReExec performs the re-execution.
func (c *Coordinator) ReExec(callback reexec.ShutdownCallbackFn, argOverrides ...string) {
	// override the overall state to stopping until the re-execution is complete
	c.state.overrideState = &coordinatorOverrideState{
		state:   agentclient.Stopping,
		message: "Re-executing",
	}
	c.reexecMgr.ReExec(callback, argOverrides...)
}

// Upgrade runs the upgrade process.
func (c *Coordinator) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade) error {
	// early check outside of upgrader before overridding the state
	if c.upgradeMgr.Upgradeable() {
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

	// override the overall state to upgrading until the re-execution is complete
	c.state.overrideState = &coordinatorOverrideState{
		state:   agentclient.Upgrading,
		message: fmt.Sprintf("Upgrading to version %s", version),
	}
	cb, err := c.upgradeMgr.Upgrade(ctx, version, sourceURI, action)
	if err != nil {
		c.state.overrideState = nil
		return err
	}
	if cb != nil {
		c.ReExec(cb)
	}
	return nil
}

func (c *Coordinator) AckUpgrade(ctx context.Context, acker acker.Acker) error {
	return c.upgradeMgr.Ack(ctx, acker)
}

// PerformAction executes an action on a unit.
func (c *Coordinator) PerformAction(ctx context.Context, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
	return c.runtimeMgr.PerformAction(ctx, unit, name, params)
}

// PerformDiagnostics executes the diagnostic action for the provided units. If no units are provided then
// it performs diagnostics for all current units.
func (c *Coordinator) PerformDiagnostics(ctx context.Context, units ...component.Unit) []runtime.ComponentUnitDiagnostic {
	return c.runtimeMgr.PerformDiagnostics(ctx, units...)
}

// Run runs the coordinator.
//
// The RuntimeManager, ConfigManager and VarsManager that is passed into NewCoordinator are also ran and lifecycle controlled by the Run.
//
// In the case that either of the above managers fail, they will all be restarted unless the context was explicitly cancelled or timed out.
func (c *Coordinator) Run(ctx context.Context) error {
	// log all changes in the state of the runtime
	go func() {
		state := make(map[string]coordinatorComponentLogState)

		sub := c.runtimeMgr.SubscribeAll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case s := <-sub.Ch():
				logState := newCoordinatorComponentLogState(&s)
				_, ok := state[s.Component.ID]
				if !ok {
					c.logger.With("component", logState).Info("New component created")
				} else {
					c.logger.With("component", logState).Info("Existing component state changed")
				}
				state[s.Component.ID] = logState
				if s.State.State == client.UnitStateStopped {
					delete(state, s.Component.ID)
				}
			}
		}
	}()

	for {
		c.state.state = agentclient.Starting
		c.state.message = "Waiting for initial configuration and composable variables"
		err := c.runner(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				c.state.state = agentclient.Stopped
				c.state.message = "Requested to be stopped"
				// do not restart
				return err
			}
		}
		c.state.state = agentclient.Failed
		c.state.message = fmt.Sprintf("Coordinator failed and will be restarted: %s", err)
		c.logger.Errorf("coordinator failed and will be restarted: %s", err)
	}
}

// DiagnosticHooks returns diagnostic hooks that can be connected to the control server to provide diagnostic
// information about the state of the Elastic Agent.
func (c *Coordinator) DiagnosticHooks() diagnostics.Hooks {
	return diagnostics.Hooks{
		{
			Name:        "pre-config",
			Filename:    "pre-config.yaml",
			Description: "current pre-configuration of the running Elastic Agent before variable substitution",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				if c.state.ast == nil {
					return []byte("error: failed no configuration by the coordinator")
				}
				cfg, err := c.state.ast.Map()
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
				if c.state.vars == nil {
					return []byte("error: failed no variables by the coordinator")
				}
				vars := make([]map[string]interface{}, 0, len(c.state.vars))
				for _, v := range c.state.vars {
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
				if c.state.ast == nil || c.state.vars == nil {
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
			Name:        "components",
			Filename:    "components.yaml",
			Description: "current expected components model of the running Elastic Agent",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				if c.state.ast == nil || c.state.vars == nil {
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
			Name:        "state",
			Filename:    "state.yaml",
			Description: "current state of running components by the Elastic Agent",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				s := c.State()
				o, err := yaml.Marshal(s)
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				return o
			},
		},
	}
}

// runner performs the actual work of running all the managers
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
			runtimeErr := <-runtimeErrCh
			c.runtimeMgrErr = runtimeErr
			configErr := <-configErrCh
			c.configMgrErr = configErr
			varsErr := <-varsErrCh
			c.varsMgrErr = varsErr
			if runtimeErr != nil && !errors.Is(runtimeErr, context.Canceled) {
				return runtimeErr
			}
			if configErr != nil && !errors.Is(configErr, context.Canceled) {
				return configErr
			}
			if varsErr != nil && !errors.Is(varsErr, context.Canceled) {
				return varsErr
			}
			return ctx.Err()
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
			c.runtimeMgrErr = runtimeErr
		case configErr := <-c.configMgr.Errors():
			c.configMgrErr = configErr
		case varsErr := <-c.varsMgr.Errors():
			c.varsMgrErr = varsErr
		case change := <-configWatcher.Watch():
			if ctx.Err() == nil {
				if err := c.processConfig(ctx, change.Config()); err != nil {
					c.state.state = agentclient.Failed
					c.state.message = err.Error()
					c.logger.Errorf("%s", err)
					change.Fail(err)
				} else {
					if err := change.Ack(); err != nil {
						err = fmt.Errorf("failed to ack configuration change: %w", err)
						c.state.state = agentclient.Failed
						c.state.message = err.Error()
						c.logger.Errorf("%s", err)
					}
				}
			}
		case vars := <-varsWatcher.Watch():
			if ctx.Err() == nil {
				if err := c.processVars(ctx, vars); err != nil {
					c.state.state = agentclient.Failed
					c.state.message = err.Error()
					c.logger.Errorf("%s", err)
				}
			}
		}
	}
}

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
		return fmt.Errorf("could not create the AST from the configuration: %w", err)
	}
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

	if err := c.upgradeMgr.Reload(cfg); err != nil {
		return fmt.Errorf("failed to reload upgrade manager configuration: %w", err)
	}

	c.state.config = cfg
	c.state.ast = rawAst

	if c.state.vars != nil {
		return c.process(ctx)
	}
	return nil
}

func (c *Coordinator) processVars(ctx context.Context, vars []*transpiler.Vars) (err error) {
	span, ctx := apm.StartSpan(ctx, "vars", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	c.state.vars = vars

	if c.state.ast != nil {
		return c.process(ctx)
	}
	return nil
}

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
	c.state.state = agentclient.Healthy
	c.state.message = "Running"
	return nil
}

func (c *Coordinator) compute() (map[string]interface{}, []component.Component, error) {
	ast := c.state.ast.Clone()
	inputs, ok := transpiler.Lookup(ast, "inputs")
	if ok {
		renderedInputs, err := transpiler.RenderInputs(inputs, c.state.vars)
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
	comps, err := c.specs.ToComponents(cfg)
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

type coordinatorState struct {
	state         agentclient.State
	message       string
	overrideState *coordinatorOverrideState

	config *config.Config
	ast    *transpiler.AST
	vars   []*transpiler.Vars
}

type coordinatorOverrideState struct {
	state   agentclient.State
	message string
}

type coordinatorComponentLogState struct {
	ID      string                             `json:"id"`
	State   string                             `json:"state"`
	Message string                             `json:"message"`
	Inputs  []coordinatorComponentUnitLogState `json:"inputs"`
	Output  coordinatorComponentUnitLogState   `json:"output,omitempty"`
}

type coordinatorComponentUnitLogState struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Message string `json:"message"`
}

func newCoordinatorComponentLogState(state *runtime.ComponentComponentState) coordinatorComponentLogState {
	var output coordinatorComponentUnitLogState
	inputs := make([]coordinatorComponentUnitLogState, 0, len(state.State.Units))
	for key, unit := range state.State.Units {
		if key.UnitType == client.UnitTypeInput {
			inputs = append(inputs, coordinatorComponentUnitLogState{
				ID:      key.UnitID,
				State:   newCoordinatorComponentStateStr(unit.State),
				Message: unit.Message,
			})
		} else {
			output = coordinatorComponentUnitLogState{
				ID:      key.UnitID,
				State:   newCoordinatorComponentStateStr(unit.State),
				Message: unit.Message,
			}
		}
	}
	return coordinatorComponentLogState{
		ID:      state.Component.ID,
		State:   newCoordinatorComponentStateStr(state.State.State),
		Message: state.State.Message,
		Inputs:  inputs,
		Output:  output,
	}
}

func newCoordinatorComponentStateStr(state client.UnitState) string {
	switch state {
	case client.UnitStateStarting:
		return "Starting"
	case client.UnitStateConfiguring:
		return "Configuring"
	case client.UnitStateDegraded:
		return "Degraded"
	case client.UnitStateHealthy:
		return "Healthy"
	case client.UnitStateFailed:
		return "Failed"
	case client.UnitStateStopping:
		return "Stopping"
	case client.UnitStateStopped:
		return "Stopped"
	}
	return "Unknown"
}

func hasState(components []runtime.ComponentComponentState, state client.UnitState) bool {
	for _, comp := range components {
		if comp.State.State == state {
			return true
		}
		for _, unit := range comp.State.Units {
			if unit.State == state {
				return true
			}
		}
	}
	return false
}
