// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/collector/otelcol"

	edotOtelCol "github.com/elastic/elastic-agent/internal/edot/otelcol"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func newValidateCommandWithArgs(_ []string, _ *cli.IOStreams, componentsFn func() (otelcol.Factories, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "validate",
		Short:         "Validates the OpenTelemetry collector configuration without running the collector",
		Long:          "Validates the OpenTelemetry collector configuration without running the collector. Validation will fail for otel-elastic hybrid configuration files. This command will return true for valid otel configurations only.",
		SilenceUsage:  true, // do not display usage on error
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgFiles, err := GetConfigFiles(cmd.Flags(), false)
			if err != nil {
				return err
			}
			return validateOtelConfig(cmd.Context(), cfgFiles, componentsFn)
		},
	}

	SetupOtelFlags(cmd.Flags())
	origHelpFunc := cmd.HelpFunc()
	cmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		hideInheritedFlags(c)
		origHelpFunc(c, s)
	})

	return cmd
}

func validateOtelConfig(ctx context.Context, cfgFiles []string, componentsFn func() (otelcol.Factories, error)) error {
	return edotOtelCol.Validate(ctx, cfgFiles, componentsFn)
}
