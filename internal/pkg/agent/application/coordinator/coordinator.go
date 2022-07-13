package coordinator

import (
	"context"
	"errors"
	"fmt"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"go.elastic.co/apm"
)

// Runner provides interface to run a manager.
type Runner interface {
	// Run runs the manager.
	Run(context.Context) error
}

// RuntimeManager provides an interface to run and update the runtime.
type RuntimeManager interface {
	Runner

	// Update updates the current components model.
	Update([]component.Component) error
}

// ConfigManager provides an interface to run and watch for configuration changes.
type ConfigManager interface {
	Runner

	// Watch returns the chanel to watch for configuration changes.
	Watch() <-chan *config.Config
}

// VarsManager provides an interface to run and watch for variable changes.
type VarsManager interface {
	Runner

	// Watch returns the chanel to watch for variable changes.
	Watch() <-chan []*transpiler.Vars
}

// ComponentsModifier is a function that takes the computed components model and modifies it before
// passing it into the components runtime manager.
type ComponentsModifier func(comps []component.Component) ([]component.Component, error)

// Coordinator manages the intersection between configuration change and updated variables.
type Coordinator struct {
	logger *logger.Logger

	specs component.RuntimeSpecs

	runtime RuntimeManager
	config  ConfigManager
	vars    VarsManager

	caps      capabilities.Capability
	modifiers []ComponentsModifier

	state coordinatorState
}

// New creates a new coordinator.
func New(logger *logger.Logger, specs component.RuntimeSpecs, runtime RuntimeManager, config ConfigManager, vars VarsManager, caps capabilities.Capability, modifiers ...ComponentsModifier) *Coordinator {
	return &Coordinator{
		logger:    logger,
		specs:     specs,
		runtime:   runtime,
		config:    config,
		vars:      vars,
		caps:      caps,
		modifiers: modifiers,
	}
}

// Run runs the coordinator.
//
// The RuntimeManager, ConfigManager and VarsManager that is passed into NewCoordinator are also ran and lifecycle controlled by the Run.
func (c *Coordinator) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	runtimeWatcher := c.runtime
	runtimeRun := make(chan bool)
	runtimeErrCh := make(chan error)
	go func(manager Runner) {
		err := manager.Run(ctx)
		close(runtimeRun)
		runtimeErrCh <- err
	}(runtimeWatcher)

	configWatcher := c.config
	configRun := make(chan bool)
	configErrCh := make(chan error)
	go func(manager Runner) {
		err := manager.Run(ctx)
		close(configRun)
		configErrCh <- err
	}(configWatcher)

	varsWatcher := c.vars
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
			if runtimeErr != nil && !errors.Is(runtimeErr, context.Canceled) {
				return runtimeErr
			}
			configErr := <-configErrCh
			if configErr != nil && !errors.Is(configErr, context.Canceled) {
				return configErr
			}
			varsErr := <-varsErrCh
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
		case cfg := <-configWatcher.Watch():
			if ctx.Err() == nil {
				if err := c.processConfig(ctx, cfg); err != nil {
					c.logger.Errorf("%s", err)
				}
			}
		case vars := <-varsWatcher.Watch():
			if ctx.Err() == nil {
				if err := c.processVars(ctx, vars); err != nil {
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

	ast := c.state.ast.Clone()
	inputs, ok := transpiler.Lookup(ast, "inputs")
	if ok {
		renderedInputs, err := transpiler.RenderInputs(inputs, c.state.vars)
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
	comps, err := c.specs.ToComponents(cfg)
	if err != nil {
		return fmt.Errorf("failed to render components: %w", err)
	}

	for _, modifier := range c.modifiers {
		comps, err = modifier(comps)
		if err != nil {
			return fmt.Errorf("failed to modify components: %w", err)
		}
	}

	c.logger.Info("Updating running component model")
	c.logger.With("components", comps).Debug("Updating running component model")
	return c.runtime.Update(comps)
}

type coordinatorState struct {
	config     *config.Config
	ast        *transpiler.AST
	vars       []*transpiler.Vars
	components []component.Component
}
