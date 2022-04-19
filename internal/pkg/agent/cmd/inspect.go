// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filters"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/pipeline"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/pipeline/emitter"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/pipeline/emitter/modifiers"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/program"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/config/operations"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/noop"
	"github.com/elastic/elastic-agent/internal/pkg/core/status"
	"github.com/elastic/elastic-agent/internal/pkg/sorted"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/go-sysinfo"
)

func newInspectCommandWithArgs(s []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Shows configuration of the agent",
		Long:  "Shows current configuration of the agent",
		Args:  cobra.ExactArgs(0),
		Run: func(c *cobra.Command, args []string) {
			if err := inspectConfig(paths.ConfigFile()); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.AddCommand(newInspectOutputCommandWithArgs(s))

	return cmd
}

func newInspectOutputCommandWithArgs(_ []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "output",
		Short: "Displays configuration generated for output",
		Long:  "Displays configuration generated for output.\nIf no output is specified list of output is displayed",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			outName, _ := c.Flags().GetString("output")
			program, _ := c.Flags().GetString("program")
			cfgPath := paths.ConfigFile()
			agentInfo, err := info.NewAgentInfo(false)
			if err != nil {
				return err
			}

			if outName == "" {
				return inspectOutputs(cfgPath, agentInfo)
			}

			return inspectOutput(cfgPath, outName, program, agentInfo)
		},
	}

	cmd.Flags().StringP("output", "o", "", "name of the output to be inspected")
	cmd.Flags().StringP("program", "p", "", "type of program to inspect, needs to be combined with output. e.g filebeat")

	return cmd
}

func inspectConfig(cfgPath string) error {
	err := tryContainerLoadPaths()
	if err != nil {
		return err
	}

	fullCfg, err := operations.LoadFullAgentConfig(cfgPath, true)
	if err != nil {
		return err
	}

	return printConfig(fullCfg)
}

func printMapStringConfig(mapStr map[string]interface{}) error {
	l, err := newErrorLogger()
	if err != nil {
		return err
	}
	caps, err := capabilities.Load(paths.AgentCapabilitiesPath(), l, status.NewController(l))
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

	data, err := yaml.Marshal(newMap)
	if err != nil {
		return errors.New(err, "could not marshal to YAML")
	}

	_, err = os.Stdout.WriteString(string(data))
	return err
}

func printConfig(cfg *config.Config) error {
	mapStr, err := cfg.ToMapStr()
	if err != nil {
		return err
	}

	return printMapStringConfig(mapStr)
}

func newErrorLogger() (*logger.Logger, error) {
	return logger.NewWithLogpLevel("", logp.ErrorLevel, false)
}

func inspectOutputs(cfgPath string, agentInfo *info.AgentInfo) error {
	l, err := newErrorLogger()
	if err != nil {
		return err
	}

	fullCfg, err := operations.LoadFullAgentConfig(cfgPath, true)
	if err != nil {
		return err
	}

	fleetConfig, err := fullCfg.ToMapStr()
	if err != nil {
		return err
	}

	isStandalone, err := isStandalone(fullCfg)
	if err != nil {
		return err
	}

	return listOutputsFromMap(l, agentInfo, fleetConfig, isStandalone)
}

func listOutputsFromConfig(log *logger.Logger, agentInfo *info.AgentInfo, cfg *config.Config, isStandalone bool) error {
	programsGroup, err := getProgramsFromConfig(log, agentInfo, cfg, isStandalone)
	if err != nil {
		return err

	}

	for k := range programsGroup {
		_, _ = os.Stdout.WriteString(k)
	}

	return nil
}

func listOutputsFromMap(log *logger.Logger, agentInfo *info.AgentInfo, cfg map[string]interface{}, isStandalone bool) error {
	c, err := config.NewConfigFrom(cfg)
	if err != nil {
		return err
	}

	return listOutputsFromConfig(log, agentInfo, c, isStandalone)
}

func inspectOutput(cfgPath, output, program string, agentInfo *info.AgentInfo) error {
	l, err := newErrorLogger()
	if err != nil {
		return err
	}

	fullCfg, err := operations.LoadFullAgentConfig(cfgPath, true)
	if err != nil {
		return err
	}

	fleetConfig, err := fullCfg.ToMapStr()
	if err != nil {
		return err
	}

	return printOutputFromMap(l, agentInfo, output, program, fleetConfig, true)
}

func printOutputFromConfig(log *logger.Logger, agentInfo *info.AgentInfo, output, programName string, cfg *config.Config, isStandalone bool) error {
	programsGroup, err := getProgramsFromConfig(log, agentInfo, cfg, isStandalone)
	if err != nil {
		return err

	}

	for k, programs := range programsGroup {
		if k != output {
			continue
		}

		var programFound bool
		for _, p := range programs {
			if programName != "" && programName != p.Spec.Cmd {
				continue
			}

			programFound = true
			_, _ = os.Stdout.WriteString(fmt.Sprintf("[%s] %s:\n", k, p.Spec.Cmd))
			err = printMapStringConfig(p.Configuration())
			if err != nil {
				return fmt.Errorf("cannot print configuration of program '%s': %w", programName, err)
			}
			_, _ = os.Stdout.WriteString("---")
		}

		if !programFound {
			return fmt.Errorf("program '%s' is not recognized within output '%s', try running `elastic-agent inspect output` to find available outputs",
				programName,
				output)
		}

		return nil
	}

	return fmt.Errorf("output '%s' is not recognized, try running `elastic-agent inspect output` to find available outputs", output)

}

func printOutputFromMap(log *logger.Logger, agentInfo *info.AgentInfo, output, programName string, cfg map[string]interface{}, isStandalone bool) error {
	c, err := config.NewConfigFrom(cfg)
	if err != nil {
		return err
	}

	return printOutputFromConfig(log, agentInfo, output, programName, c, isStandalone)
}

func getProgramsFromConfig(log *logger.Logger, agentInfo *info.AgentInfo, cfg *config.Config, isStandalone bool) (map[string][]program.Program, error) {
	monitor := noop.NewMonitor()
	router := &inmemRouter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	composableCtrl, err := composable.New(log, cfg)
	if err != nil {
		return nil, err
	}

	composableWaiter := newWaitForCompose(composableCtrl)
	configModifiers := &pipeline.ConfigModifiers{
		Decorators: []pipeline.DecoratorFunc{modifiers.InjectMonitoring},
		Filters:    []pipeline.FilterFunc{filters.StreamChecker},
	}

	if !isStandalone {
		sysInfo, err := sysinfo.Host()
		if err != nil {
			return nil, errors.New(err,
				"fail to get system information",
				errors.TypeUnexpected)
		}
		configModifiers.Filters = append(configModifiers.Filters, modifiers.InjectFleet(cfg, sysInfo.Info(), agentInfo))
	}

	caps, err := capabilities.Load(paths.AgentCapabilitiesPath(), log, status.NewController(log))
	if err != nil {
		return nil, err
	}

	emit, err := emitter.New(
		ctx,
		log,
		agentInfo,
		composableWaiter,
		router,
		configModifiers,
		caps,
		monitor,
	)
	if err != nil {
		return nil, err
	}

	if err := emit(ctx, cfg); err != nil {
		return nil, err
	}
	composableWaiter.Wait()

	// add the fleet-server input to default programs list
	// this does not correspond to the actual config that fleet-server uses as it's in fleet.yml and not part of the assembled config (cfg)
	fleetCFG, err := cfg.ToMapStr()
	if err != nil {
		return nil, err
	}
	if fleetInput := getFleetInput(fleetCFG); fleetInput != nil {
		ast, err := transpiler.NewAST(fleetInput)
		if err != nil {
			return nil, err
		}
		router.programs["default"] = append(router.programs["default"], program.Program{
			Spec: program.Spec{
				Name: "fleet-server",
				Cmd:  "fleet-server",
			},
			Config: ast,
		})
	}

	return router.programs, nil
}

func getFleetInput(o map[string]interface{}) map[string]interface{} {
	arr, ok := o["inputs"].([]interface{})
	if !ok {
		return nil
	}
	for _, iface := range arr {
		input, ok := iface.(map[string]interface{})
		if !ok {
			continue
		}
		t, ok := input["type"]
		if !ok {
			continue
		}
		if t.(string) == "fleet-server" {
			return input
		}
	}
	return nil
}

type inmemRouter struct {
	programs map[string][]program.Program
}

func (r *inmemRouter) Routes() *sorted.Set {
	return nil
}

func (r *inmemRouter) Route(_ context.Context, _ string, grpProg map[pipeline.RoutingKey][]program.Program) error {
	r.programs = grpProg
	return nil
}

func (r *inmemRouter) Shutdown() {}

type waitForCompose struct {
	controller composable.Controller
	done       chan bool
}

func newWaitForCompose(wrapped composable.Controller) *waitForCompose {
	return &waitForCompose{
		controller: wrapped,
		done:       make(chan bool),
	}
}

func (w *waitForCompose) Run(ctx context.Context, cb composable.VarsCallback) error {
	err := w.controller.Run(ctx, func(vars []*transpiler.Vars) {
		cb(vars)
		w.done <- true
	})
	return err
}

func (w *waitForCompose) Wait() {
	<-w.done
}

func isStandalone(cfg *config.Config) (bool, error) {
	c, err := configuration.NewFromConfig(cfg)
	if err != nil {
		return false, err
	}

	return configuration.IsStandalone(c.Fleet), nil
}
