// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
)

func newValidateCommandWithArgs(_ []string, _ *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "validate",
		Short:         "Validates the config without running the collector",
		SilenceUsage:  true, // do not display usage on error
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfgFile := paths.ConfigFile()
			return validateOtelConfig(ctx, cfgFile)
		},
	}

	return cmd
}

func validateOtelConfig(ctx context.Context, cfgFile string) error {
	if runAsOtel := otel.IsOtelConfig(ctx, cfgFile); !runAsOtel {
		return fmt.Errorf("%q is not an otel config. file should be named 'otel.yml', 'otlp.yml' or 'otelcol.yml'", cfgFile)
	}

	return otel.Validate(ctx, cfgFile)
}
