// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package componentvalidation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vars"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/config/operations"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func EnsureNoServiceComponentIssues() error {
	ctx := context.Background()
	l, err := newErrorLogger()
	if err != nil {
		return fmt.Errorf("failed to create error logger: %w", err)
	}
	// this forces the component calculation to always compute with no root
	// this allows any runtime preventions to error for a component when it has a no root support
	comps, err := GetComponentsFromPolicy(ctx, l, paths.ConfigFile(), 0, forceNonRoot)
	if err != nil {
		return fmt.Errorf("failed to create component model from policy: %w", err)
	}
	var errs []error
	for _, comp := range comps {
		if comp.InputSpec == nil {
			// no spec (safety net)
			continue
		}
		if comp.InputSpec.Spec.Service == nil {
			// not a service component, allowed to exist (even if it needs root)
			continue
		}
		if comp.Err != nil {
			// service component has an error (most likely because it cannot run without root)
			errs = append(errs, fmt.Errorf("%s -> %w", comp.ID, comp.Err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("unable to switch to unprivileged mode due to the following service based components having issues: %w", errors.Join(errs...))
	}
	return nil
}

func newErrorLogger() (*logger.Logger, error) {
	return logger.NewWithLogpLevel("", logp.ErrorLevel, false)
}

func forceNonRoot(detail component.PlatformDetail) component.PlatformDetail {
	detail.User.Root = false
	return detail
}

func GetComponentsFromPolicy(ctx context.Context, l *logger.Logger, cfgPath string, variablesWait time.Duration, platformModifiers ...component.PlatformModifier) ([]component.Component, error) {
	// Load the requirements before trying to load the configuration. These should always load
	// even if the configuration is wrong.
	platform, err := component.LoadPlatformDetail(platformModifiers...)
	if err != nil {
		return nil, fmt.Errorf("failed to gather system information: %w", err)
	}
	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return nil, fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}

	isAdmin, err := utils.HasRoot()
	if err != nil {
		return nil, fmt.Errorf("error checking for root/Administrator privileges: %w", err)
	}

	m, otel, lvl, err := GetConfigWithVariables(ctx, l, cfgPath, variablesWait, !isAdmin)
	if err != nil {
		return nil, err
	}

	rawCfg, err := operations.LoadFullAgentConfig(ctx, l, cfgPath, true, !isAdmin)
	if err != nil {
		return nil, err
	}
	cfg, err := configuration.NewFromConfig(rawCfg)
	if err != nil {
		return nil, err
	}

	monitorFn, err := GetMonitoringFn(ctx, l, m, otel)
	if err != nil {
		return nil, fmt.Errorf("failed to get monitoring: %w", err)
	}

	agentInfo, err := info.NewAgentInfoWithLog(ctx, "error", false)
	if err != nil {
		return nil, fmt.Errorf("could not load agent info: %w", err)
	}

	// Compute the components from the computed configuration.
	comps, err := specs.ToComponents(
		m,
		cfg.Settings.Internal.Runtime,
		nil,
		monitorFn,
		lvl,
		agentInfo,
		map[string]uint64{},
		map[string]bool{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to render components: %w", err)
	}

	return comps, nil
}

func GetMonitoringFn(ctx context.Context, logger *logger.Logger, cfg map[string]interface{}, otelCfg *confmap.Conf) (component.GenerateMonitoringCfgFn, error) {
	config, err := config.NewConfigFrom(cfg)
	if err != nil {
		return nil, err
	}

	agentCfg := configuration.DefaultConfiguration()
	if err := config.UnpackTo(agentCfg); err != nil {
		return nil, err
	}

	agentInfo, err := info.NewAgentInfoWithLog(ctx, "error", false)
	if err != nil {
		return nil, fmt.Errorf("could not load agent info: %w", err)
	}

	monitor := componentmonitoring.New(
		agentCfg.Settings.V1MonitoringEnabled,
		agentCfg.Settings.DownloadConfig.OS(),
		agentCfg.Settings.MonitoringConfig,
		agentInfo,
		logger,
	)
	return monitor.MonitoringConfig, nil
}

func GetConfigWithVariables(ctx context.Context, l *logger.Logger, cfgPath string, timeout time.Duration, unprivileged bool) (map[string]interface{}, *confmap.Conf, logp.Level, error) {

	cfg, err := operations.LoadFullAgentConfig(ctx, l, cfgPath, true, unprivileged)
	if err != nil {
		return nil, nil, logp.InfoLevel, err
	}
	lvl, err := getLogLevel(cfg, cfgPath)
	if err != nil {
		return nil, nil, logp.InfoLevel, err
	}
	m, err := cfg.ToMapStr()
	if err != nil {
		return nil, nil, lvl, err
	}
	ast, err := transpiler.NewAST(m)
	if err != nil {
		return nil, nil, lvl, fmt.Errorf("could not create the AST from the configuration: %w", err)
	}

	// Wait for the variables based on the timeout.
	vars, err := vars.WaitForVariables(ctx, l, cfg, timeout)
	if err != nil {
		return nil, nil, lvl, fmt.Errorf("failed to gather variables: %w", err)
	}

	// Render the inputs using the discovered inputs.
	inputs, ok := transpiler.Lookup(ast, "inputs")
	if ok {
		renderedInputs, _, err := transpiler.RenderInputs(inputs, vars)
		if err != nil {
			return nil, nil, lvl, fmt.Errorf("rendering inputs failed: %w", err)
		}
		err = transpiler.Insert(ast, renderedInputs, "inputs")
		if err != nil {
			return nil, nil, lvl, fmt.Errorf("inserting rendered inputs failed: %w", err)
		}
	}
	m, err = ast.Map()
	if err != nil {
		return nil, nil, lvl, fmt.Errorf("failed to convert ast to map[string]interface{}: %w", err)
	}
	return m, cfg.OTel, lvl, nil
}

func getLogLevel(rawCfg *config.Config, cfgPath string) (logp.Level, error) {
	cfg, err := configuration.NewFromConfig(rawCfg)
	if err != nil {
		return logger.DefaultLogLevel, fmt.Errorf("could not parse configuration file %s: %w", cfgPath, err)
	}
	if cfg.Settings.LoggingConfig != nil {
		return cfg.Settings.LoggingConfig.Level, nil
	}
	return logger.DefaultLogLevel, nil
}
