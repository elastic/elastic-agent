// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/service"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/config/operations"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func newInspectCommandWithArgs(s []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Shows configuration of the agent",
		Long: `Shows current configuration of the agent.

By default variable substitution is not performed. Use the --variables flag to enable variable substitution. The
first set of computed variables are used when only the --variables flag is defined. This can prevent some of the
dynamic providers (kubernetes, docker, etc.) from providing all the possible variables it could have discovered if given
more time. The --variables-wait allows an amount of time to be provided for variable discovery, when set it will
wait that amount of time before using the variables for the configuration.
`,
		Args: cobra.ExactArgs(0),
		Run: func(c *cobra.Command, args []string) {
			var opts inspectConfigOpts
			opts.variables, _ = c.Flags().GetBool("variables")
			opts.variablesWait, _ = c.Flags().GetDuration("variables-wait")

			ctx, cancel := context.WithCancel(context.Background())
			service.HandleSignals(func() {}, cancel)
			if err := inspectConfig(ctx, paths.ConfigFile(), opts, streams); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().Bool("variables", false, "render configuration with variables substituted")
	cmd.Flags().Duration("variables-wait", time.Duration(0), "wait this amount of time for variables before performing substitution")

	cmd.AddCommand(newInspectComponentsCommandWithArgs(s, streams))

	return cmd
}

func newInspectComponentsCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "components [id]",
		Short: "Displays the components model for the configuration",
		Long: `Displays the generated components model for the current configuration.

By default the configuration for each unit inside of a component is not returned. Use --show-config to display the
configuration in all the units.

A specific component can be selected by its ID and only that component and all its units will be returned. Because its
possible for a component to have many units the configuration for each unit is still not provided by default. Use
--show-config to display the configuration in all the units.

A specific unit inside of a component can be selected by using <component_id>/<unit_id> and only that unit will be
returned. In this mode the configuration is provided by default, using the --show-config is a noop.

The selected input or output runtime specification for a component is never provided unless enabled with --show-spec.

Variable substitution is always performed when computing the components, and it cannot be disabled. By default only the
first set of computed variables are used. This can prevent some of the dynamic providers (kubernetes, docker, etc.) from
providing all the possible variables it could have discovered if given more time. The --variables-wait allows an
amount of time to be provided for variable discovery, when set it will wait that amount of time before using the
variables for the configuration.
`,
		Args: cobra.MaximumNArgs(1),
		Run: func(c *cobra.Command, args []string) {
			var opts inspectComponentsOpts
			if len(args) > 0 {
				opts.id = args[0]
			}
			opts.showConfig, _ = c.Flags().GetBool("show-config")
			opts.showSpec, _ = c.Flags().GetBool("show-spec")
			opts.variablesWait, _ = c.Flags().GetDuration("variables-wait")

			ctx, cancel := context.WithCancel(context.Background())
			service.HandleSignals(func() {}, cancel)
			if err := inspectComponents(ctx, paths.ConfigFile(), opts, streams); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().Bool("show-config", false, "show the configuration for all units")
	cmd.Flags().Bool("show-spec", false, "show the runtime specification for a component")
	cmd.Flags().Duration("variables-wait", time.Duration(0), "wait this amount of time for variables before performing substitution")

	return cmd
}

type inspectConfigOpts struct {
	variables     bool
	variablesWait time.Duration
}

func inspectConfig(ctx context.Context, cfgPath string, opts inspectConfigOpts, streams *cli.IOStreams) error {
	err := tryContainerLoadPaths()
	if err != nil {
		return err
	}

	l, err := newErrorLogger()
	if err != nil {
		return err
	}

	fullCfg, err := operations.LoadFullAgentConfig(l, cfgPath, true)
	if err != nil {
		return err
	}

	if !opts.variables {
		return printConfig(fullCfg, l, streams)
	}
	cfg, err := getConfigWithVariables(ctx, l, cfgPath, opts.variablesWait)
	if err != nil {
		return err
	}
	return printMapStringConfig(cfg, streams)
}

func printMapStringConfig(mapStr map[string]interface{}, streams *cli.IOStreams) error {
	data, err := yaml.Marshal(mapStr)
	if err != nil {
		return errors.New(err, "could not marshal to YAML")
	}

	_, err = streams.Out.Write(data)
	return err
}

func printConfig(cfg *config.Config, l *logger.Logger, streams *cli.IOStreams) error {
	caps, err := capabilities.Load(paths.AgentCapabilitiesPath(), l)
	if err != nil {
		return err
	}

	mapStr, err := cfg.ToMapStr()
	if err != nil {
		return err
	}
	newCfg, err := caps.Apply(mapStr)
	if err != nil {
		return errors.New(err, "failed to apply capabilities")
	}
	newMap, ok := newCfg.(map[string]interface{})
	if !ok {
		return errors.New("config returned from capabilities has invalid type")
	}

	return printMapStringConfig(newMap, streams)
}

type inspectComponentsOpts struct {
	id            string
	showConfig    bool
	showSpec      bool
	variablesWait time.Duration
}

func inspectComponents(ctx context.Context, cfgPath string, opts inspectComponentsOpts, streams *cli.IOStreams) error {
	l, err := newErrorLogger()
	if err != nil {
		return err
	}

	// Ensure that when running inside a container that the correct paths are used.
	err = tryContainerLoadPaths()
	if err != nil {
		return err
	}

	// Load the requirements before trying to load the configuration. These should always load
	// even if the configuration is wrong.
	platform, err := component.LoadPlatformDetail()
	if err != nil {
		return fmt.Errorf("failed to gather system information: %w", err)
	}
	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}

	m, err := getConfigWithVariables(ctx, l, cfgPath, opts.variablesWait)
	if err != nil {
		return err
	}

	// Compute the components from the computed configuration.
	comps, err := specs.ToComponents(m)
	if err != nil {
		return fmt.Errorf("failed to render components: %w", err)
	}

	// ID provided.
	if opts.id != "" {
		splitID := strings.SplitN(opts.id, "/", 2)
		compID := splitID[0]
		unitID := ""
		if len(splitID) > 1 {
			unitID = splitID[1]
		}
		comp, ok := findComponent(comps, compID)
		if ok {
			if unitID != "" {
				unit, ok := findUnit(comp, unitID)
				if ok {
					return printUnit(unit, streams)
				}
				return fmt.Errorf("unable to find unit with ID: %s/%s", compID, unitID)
			}
			if !opts.showSpec {
				comp.Spec = component.InputRuntimeSpec{}
			}
			if !opts.showConfig {
				for key, unit := range comp.Units {
					unit.Config = nil
					comp.Units[key] = unit
				}
			}
			return printComponent(comp, streams)
		}
		return fmt.Errorf("unable to find component with ID: %s", compID)
	}

	// Hide configuration unless toggled on.
	if !opts.showConfig {
		for i, comp := range comps {
			for key, unit := range comp.Units {
				unit.Config = nil
				comp.Units[key] = unit
			}
			comps[i] = comp
		}
	}

	// Hide runtime specification unless toggled on.
	if !opts.showSpec {
		for i, comp := range comps {
			comp.Spec = component.InputRuntimeSpec{}
			comps[i] = comp
		}
	}

	return printComponents(comps, streams)
}

func getConfigWithVariables(ctx context.Context, l *logger.Logger, cfgPath string, timeout time.Duration) (map[string]interface{}, error) {
	caps, err := capabilities.Load(paths.AgentCapabilitiesPath(), l)
	if err != nil {
		return nil, fmt.Errorf("failed to determine capabilities: %w", err)
	}

	cfg, err := operations.LoadFullAgentConfig(l, cfgPath, true)
	if err != nil {
		return nil, err
	}
	m, err := cfg.ToMapStr()
	if err != nil {
		return nil, err
	}
	ast, err := transpiler.NewAST(m)
	if err != nil {
		return nil, fmt.Errorf("could not create the AST from the configuration: %w", err)
	}

	var ok bool
	updatedAst, err := caps.Apply(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to apply capabilities: %w", err)
	}
	ast, ok = updatedAst.(*transpiler.AST)
	if !ok {
		return nil, fmt.Errorf("failed to transform object returned from capabilities to AST: %w", err)
	}

	// Wait for the variables based on the timeout.
	vars, err := waitForVariables(ctx, l, cfg, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to gather variables: %w", err)
	}

	// Render the inputs using the discovered inputs.
	inputs, ok := transpiler.Lookup(ast, "inputs")
	if ok {
		renderedInputs, err := transpiler.RenderInputs(inputs, vars)
		if err != nil {
			return nil, fmt.Errorf("rendering inputs failed: %w", err)
		}
		err = transpiler.Insert(ast, renderedInputs, "inputs")
		if err != nil {
			return nil, fmt.Errorf("inserting rendered inputs failed: %w", err)
		}
	}
	m, err = ast.Map()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ast to map[string]interface{}: %w", err)
	}
	return m, nil
}

type varsWait struct {
	vars []*transpiler.Vars
	err  error
}

func waitForVariables(ctx context.Context, l *logger.Logger, cfg *config.Config, wait time.Duration) ([]*transpiler.Vars, error) {
	var cancel context.CancelFunc
	var vars []*transpiler.Vars

	composable, err := composable.New(l, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create composable controller: %w", err)
	}

	hasTimeout := false
	if wait > time.Duration(0) {
		hasTimeout = true
		ctx, cancel = context.WithTimeout(ctx, wait)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		for {
			select {
			case <-ctx.Done():
				if err == nil {
					err = ctx.Err()
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					err = nil
				}
				return err
			case cErr := <-composable.Errors():
				err = cErr
				if err != nil {
					cancel()
				}
			case cVars := <-composable.Watch():
				vars = cVars
				if !hasTimeout {
					cancel()
				}
			}
		}
	})

	g.Go(func() error {
		err := composable.Run(ctx)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			err = nil
		}
		return err
	})

	err = g.Wait()
	if err != nil {
		return nil, err
	}
	return vars, nil
}

func printComponents(components []component.Component, streams *cli.IOStreams) error {
	topLevel := struct {
		Components []component.Component `yaml:"components"`
	}{
		Components: components,
	}
	data, err := yaml.Marshal(topLevel)
	if err != nil {
		return errors.New(err, "could not marshal to YAML")
	}
	_, err = streams.Out.Write(data)
	return err
}

func printComponent(comp component.Component, streams *cli.IOStreams) error {
	data, err := yaml.Marshal(comp)
	if err != nil {
		return errors.New(err, "could not marshal to YAML")
	}
	_, err = streams.Out.Write(data)
	return err
}

func printUnit(unit component.Unit, streams *cli.IOStreams) error {
	data, err := yaml.Marshal(unit)
	if err != nil {
		return errors.New(err, "could not marshal to YAML")
	}
	_, err = streams.Out.Write(data)
	return err
}

func findUnit(comp component.Component, id string) (component.Unit, bool) {
	for _, unit := range comp.Units {
		if unit.ID == id {
			return unit, true
		}
	}
	return component.Unit{}, false
}

func findComponent(components []component.Component, id string) (component.Component, bool) {
	for _, comp := range components {
		if comp.ID == id {
			return comp, true
		}
	}
	return component.Component{}, false
}

func newErrorLogger() (*logger.Logger, error) {
	return logger.NewWithLogpLevel("", logp.ErrorLevel, false)
}
