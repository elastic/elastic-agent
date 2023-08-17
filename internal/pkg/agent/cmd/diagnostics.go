// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
)

func newDiagnosticsCommand(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diagnostics",
		Short: "Gather diagnostics information from the Elastic Agent and write it to a zip archive",
		Long:  "This command gathers diagnostics information from the Elastic Agent and writes it to a zip archive.",
		Run: func(c *cobra.Command, args []string) {
			if err := diagnosticCmd(streams, c); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringP("file", "f", "", "name of the output diagnostics zip archive")

	return cmd
}

func diagnosticCmd(streams *cli.IOStreams, cmd *cobra.Command) error {
	fileName, _ := cmd.Flags().GetString("file")
	if fileName == "" {
		ts := time.Now().UTC()
		fileName = "elastic-agent-diagnostics-" + ts.Format("2006-01-02T15-04-05Z07-00") + ".zip" // RFC3339 format that replaces : with -, so it will work on Windows
	}

	ctx := handleSignal(context.Background())

	daemon := client.New()
	err := daemon.Connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer daemon.Disconnect()

	agentDiag, err := daemon.DiagnosticAgent(ctx)
	if err != nil {
		fmt.Fprintf(streams.Err, "[WARNING]: failed to fetch agent diagnostics: %s", err)
	}

	unitDiags, err := daemon.DiagnosticUnits(ctx)
	if err != nil {
		fmt.Fprintf(streams.Err, "[WARNING]: failed to fetch unit diagnostics: %s", err)
	}

	compDiags, err := daemon.DiagnosticComponents(ctx, additionalDiags)
	if err != nil {
		fmt.Fprintf(streams.Err, "[WARNING]: failed to fetch component diagnostics: %s", err)
	}

	if len(compDiags) == 0 && len(unitDiags) == 0 && len(agentDiag) == 0 {
		return fmt.Errorf("no diags could be fetched")
	}

	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := diagnostics.ZipArchive(streams.Err, f, agentDiag, unitDiags); err != nil {
		return fmt.Errorf("unable to create archive %q: %w", fileName, err)
	}
	fmt.Fprintf(streams.Out, "Created diagnostics archive %q\n", fileName)
	fmt.Fprintln(streams.Out, "***** WARNING *****\nCreated archive may contain plain text credentials.\nEnsure that files in archive are redacted before sharing.\n*******************")
	return nil
}
