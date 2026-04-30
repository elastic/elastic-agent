// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install/componentvalidation"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config/operations"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func inspectOtelCmd(ctx context.Context, cfgPath string, streams *cli.IOStreams) error {
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
		return fmt.Errorf("error parsing agent configuration: %w", err)
	}

	components, err := componentvalidation.GetComponentsFromPolicy(ctx, l, cfgPath, 0)

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
