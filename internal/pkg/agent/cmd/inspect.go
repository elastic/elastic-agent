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
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/service"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vars"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/config/operations"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func newInspectCommandWithArgs(s []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Show current configuration of the Elastic Agent",
		Long: `This command shows the current configuration of the Elastic Agent.

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
			opts.includeMonitoring, _ = c.Flags().GetBool("monitoring")
			opts.variablesWait, _ = c.Flags().GetDuration("variables-wait")

			opts.variables = opts.variables || c.Flags().Changed("variables-wait")

			ctx, cancel := context.WithCancel(context.Background())
			service.HandleSignals(func() {}, cancel)
			if err := inspectConfig(ctx, paths.ConfigFile(), opts, streams); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().Bool("variables", false, "render configuration with variables substituted")
	cmd.Flags().Bool("monitoring", false, "includes monitoring configuration (implies --variables)")
	cmd.Flags().Duration("variables-wait", time.Duration(0), "wait this amount of time for variables before performing substitution (implies --variables)")

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
	variables         bool
	includeMonitoring bool
	variablesWait     time.Duration
}

func inspectConfig(ctx context.Context, cfgPath string, opts inspectConfigOpts, streams *cli.IOStreams) error {
	l, err := newErrorLogger()
	if err != nil {
		return err
	}

	if !opts.variables && !opts.includeMonitoring {
		fullCfg, err := operations.LoadFullAgentConfig(l, cfgPath, true)
		if err != nil {
			return err
		}
		return printConfig(fullCfg, l, streams)
	}

	cfg, lvl, err := getConfigWithVariables(ctx, l, cfgPath, opts.variablesWait)
	if err != nil {
		return err
	}

	agentInfo, err := info.NewAgentInfoWithLog("error", false)
	if err != nil {
		return fmt.Errorf("could not load agent info: %w", err)
	}

	if opts.includeMonitoring {
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

		monitorFn, err := getMonitoringFn(cfg)
		if err != nil {
			return fmt.Errorf("failed to get monitoring: %w", err)
		}
		components, err := specs.PolicyToComponents(cfg, lvl, agentInfo)
		if err != nil {
			return fmt.Errorf("failed to get binary mappings: %w", err)
		}

		// The monitoring config depends on a map from component id to
		// binary name.
		binaryMapping := make(map[string]string)
		for _, component := range components {
			if spec := component.InputSpec; spec != nil {
				binaryMapping[component.ID] = spec.BinaryName
			}
		}
		monitorCfg, err := monitorFn(cfg, components, binaryMapping)
		if err != nil {
			return fmt.Errorf("failed to get monitoring config: %w", err)
		}

		if monitorCfg != nil {
			rawCfg := config.MustNewConfigFrom(cfg)

			if err := rawCfg.Merge(monitorCfg); err != nil {
				return fmt.Errorf("failed to merge monitoring config: %w", err)
			}

			cfg, err = rawCfg.ToMapStr()
			if err != nil {
				return fmt.Errorf("failed to convert monitoring config: %w", err)
			}
		}
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
	mapStr, err := cfg.ToMapStr()
	if err != nil {
		return err
	}
	return printMapStringConfig(mapStr, streams)
}

type inspectComponentsOpts struct {
	id            string
	showConfig    bool
	showSpec      bool
	variablesWait time.Duration
}

// returns true if the given Capabilities config blocks the given component.
func blockedByCaps(c component.Component, caps capabilities.Capabilities) bool {
	return !caps.AllowInput(c.InputType()) || !caps.AllowOutput(c.OutputType())
}

func inspectComponents(ctx context.Context, cfgPath string, opts inspectComponentsOpts, streams *cli.IOStreams) error {
	l, err := newErrorLogger()
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

	m, lvl, err := getConfigWithVariables(ctx, l, cfgPath, opts.variablesWait)
	if err != nil {
		return err
	}

	monitorFn, err := getMonitoringFn(m)
	if err != nil {
		return fmt.Errorf("failed to get monitoring: %w", err)
	}

	agentInfo, err := info.NewAgentInfoWithLog("error", false)
	if err != nil {
		return fmt.Errorf("could not load agent info: %w", err)
	}

	// Compute the components from the computed configuration.
	comps, err := specs.ToComponents(m, monitorFn, lvl, agentInfo)
	if err != nil {
		return fmt.Errorf("failed to render components: %w", err)
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
			comp.InputSpec = nil
			comp.ShipperSpec = nil
			comps[i] = comp
		}
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
			return printComponent(comp, streams)
		}
		return fmt.Errorf("unable to find component with ID: %s", compID)
	}

	// Separate any components that are blocked by capabilities config
	caps, err := capabilities.LoadFile(paths.AgentCapabilitiesPath(), l)
	if err != nil {
		return err
	}
	allowed := []component.Component{}
	blocked := []component.Component{}
	for _, c := range comps {
		if blockedByCaps(c, caps) {
			blocked = append(blocked, c)
		} else {
			allowed = append(allowed, c)
		}
	}

	return printComponents(allowed, blocked, streams)
}

func getMonitoringFn(cfg map[string]interface{}) (component.GenerateMonitoringCfgFn, error) {
	config, err := config.NewConfigFrom(cfg)
	if err != nil {
		return nil, err
	}

	agentCfg := configuration.DefaultConfiguration()
	if err := config.Unpack(agentCfg); err != nil {
		return nil, err
	}

	agentInfo, err := info.NewAgentInfoWithLog("error", false)
	if err != nil {
		return nil, fmt.Errorf("could not load agent info: %w", err)
	}

	monitor := monitoring.New(agentCfg.Settings.V1MonitoringEnabled, agentCfg.Settings.DownloadConfig.OS(), agentCfg.Settings.MonitoringConfig, agentInfo)
	return monitor.MonitoringConfig, nil
}

func getConfigWithVariables(ctx context.Context, l *logger.Logger, cfgPath string, timeout time.Duration) (map[string]interface{}, logp.Level, error) {

	cfg, err := operations.LoadFullAgentConfig(l, cfgPath, true)
	if err != nil {
		return nil, logp.InfoLevel, err
	}
	lvl, err := getLogLevel(cfg, cfgPath)
	if err != nil {
		return nil, logp.InfoLevel, err
	}
	m, err := cfg.ToMapStr()
	if err != nil {
		return nil, lvl, err
	}
	ast, err := transpiler.NewAST(m)
	if err != nil {
		return nil, lvl, fmt.Errorf("could not create the AST from the configuration: %w", err)
	}

	// Wait for the variables based on the timeout.
	vars, err := vars.WaitForVariables(ctx, l, cfg, timeout)
	if err != nil {
		return nil, lvl, fmt.Errorf("failed to gather variables: %w", err)
	}

	// Render the inputs using the discovered inputs.
	inputs, ok := transpiler.Lookup(ast, "inputs")
	if ok {
		renderedInputs, err := transpiler.RenderInputs(inputs, vars)
		if err != nil {
			return nil, lvl, fmt.Errorf("rendering inputs failed: %w", err)
		}
		err = transpiler.Insert(ast, renderedInputs, "inputs")
		if err != nil {
			return nil, lvl, fmt.Errorf("inserting rendered inputs failed: %w", err)
		}
	}
	m, err = ast.Map()
	if err != nil {
		return nil, lvl, fmt.Errorf("failed to convert ast to map[string]interface{}: %w", err)
	}
	return m, lvl, nil
}

func getLogLevel(rawCfg *config.Config, cfgPath string) (logp.Level, error) {
	cfg, err := configuration.NewFromConfig(rawCfg)
	if err != nil {
		return logger.DefaultLogLevel, errors.New(err,
			fmt.Sprintf("could not parse configuration file %s", cfgPath),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, cfgPath))
	}
	if cfg.Settings.LoggingConfig != nil {
		return cfg.Settings.LoggingConfig.Level, nil
	}
	return logger.DefaultLogLevel, nil
}

func printComponents(
	components []component.Component,
	blocked []component.Component,
	streams *cli.IOStreams,
) error {
	topLevel := struct {
		Components []component.Component `yaml:"components"`
		Blocked    []component.Component `yaml:"blocked_by_capabilities"`
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
