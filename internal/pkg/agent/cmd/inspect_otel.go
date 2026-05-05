// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install/componentvalidation"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/config/operations"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func inspectOtelCmd(ctx context.Context, cfgPath string, streams *cli.IOStreams, opts inspectConfigOpts) error {
	l, err := newErrorLogger()
	if err != nil {
		return fmt.Errorf("error creating logger: %w", err)
	}

	isAdmin, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("error checking for root/Administrator privileges: %w", err)
	}
	fullCfg, err := operations.LoadFullAgentConfig(ctx, l, cfgPath, true, !isAdmin)
	if err != nil {
		return fmt.Errorf("error loading agent config: %w", err)
	}

	agentInfo, err := info.NewAgentInfoWithLog(ctx, "error", false)
	if err != nil {
		return fmt.Errorf("could not load agent info: %w", err)
	}

	agentCfg, err := configuration.NewFromConfig(fullCfg)
	if err != nil {
		return fmt.Errorf("error loading agent config: %w", err)
	}
	platform, err := component.LoadPlatformDetail()
	if err != nil {
		return fmt.Errorf("failed to gather system information: %w", err)
	}
	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}

	if err := diagnostics.AddSecretMarkers(l, fullCfg); err != nil {
		return fmt.Errorf("failed to add diagnostics marker: %v", err)
	}

	cfg, err := fullCfg.ToMapStr()
	if err != nil {
		return fmt.Errorf("failed to converting config: %w", err)
	}

	lvl := logger.DefaultLogLevel
	if agentCfg.Settings.LoggingConfig != nil {
		lvl = agentCfg.Settings.LoggingConfig.Level
	}

	if opts.includeMonitoring {
		// Load the requirements before trying to load the configuration. These should always load
		// even if the configuration is wrong.

		monitorFn, err := componentvalidation.GetMonitoringFn(ctx, l, cfg, fullCfg.OTel)
		if err != nil {
			return fmt.Errorf("failed to get monitoring: %w", err)
		}
		components, err := specs.PolicyToComponents(cfg, agentCfg.Settings.Internal.Runtime, lvl, agentInfo, map[string]bool{})
		if err != nil {
			return fmt.Errorf("failed to get binary mappings: %w", err)
		}

		// service units like endpoint are special; they require a PID to monitor.
		// however, `inspect` doesn't talk to the coordinator backend, which means it can't know their actual PID from this point in the code
		// instead, we look for service units and create a fake PID, so we print the monitoring config anyway.
		serviceUnitExists := false
		fakeServicePids := map[string]uint64{}

		for _, component := range components {
			if spec := component.InputSpec; spec != nil {
				if spec.Spec.Service != nil {
					serviceUnitExists = true
					fakeServicePids[component.ID] = 1234
				}
			}
		}
		monitorCfg, err := monitorFn(cfg, components, fakeServicePids)
		if err != nil {
			return fmt.Errorf("failed to get monitoring config: %w", err)
		}

		if monitorCfg != nil {

			// see above comment; because we don't know endpoint's actual PID, we need to make a fake one. Warn the user.
			if serviceUnitExists {
				keys := make([]string, 0, len(fakeServicePids))
				for k := range fakeServicePids {
					keys = append(keys, k)
				}
				fmt.Fprintf(streams.Err, "WARNING: the inspect command can't accurately produce monitoring configs for service units: %v. Use the diagnostics command to get the real config used for monitoring these components\n", keys)
			}

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

	components, err := specs.ToComponents(cfg, agentCfg.Settings.Internal.Runtime, nil, nil, lvl, agentInfo, map[string]uint64{}, map[string]bool{})

	otelComponents := make([]component.Component, 0, len(components))
	for _, c := range components {
		if c.RuntimeManager == component.OtelRuntimeManager {
			otelComponents = append(otelComponents, c)
		}
	}

	if len(otelComponents) == 0 {
		fmt.Fprintln(streams.Out, "No OpenTelemetry components found in the configuration.")
		return nil
	}

	model := &component.Model{Components: otelComponents}
	componentOtelCfg, err := translate.GetOtelConfig(model, agentInfo, agentCfg.Settings.Internal.Runtime, nil, l)
	if err != nil {
		return fmt.Errorf("failed to generate otel config: %w", err)
	}

	return printMapStringConfig(componentOtelCfg.ToStringMap(), streams)
}
