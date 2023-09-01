// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"

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
	cmd.Flags().BoolP("cpu-profile", "p", false, "wait to collect a CPU profile")

	return cmd
}

func diagnosticCmd(streams *cli.IOStreams, cmd *cobra.Command) error {
	filepath, _ := cmd.Flags().GetString("file")
	if filepath == "" {
		ts := time.Now().UTC()
		filepath = "elastic-agent-diagnostics-" + ts.Format("2006-01-02T15-04-05Z07-00") + ".zip" // RFC3339 format that replaces : with -, so it will work on Windows
	}

	ctx := handleSignal(context.Background())

	// 1st create the file to store the diagnostics, if it fails, anything else
	// is pointless.
	f, err := createFile(filepath)
	if err != nil {
		return fmt.Errorf("could not create diagnostics file %q: %w", filepath, err)
	}
	defer f.Close()

	cpuProfile, _ := cmd.Flags().GetBool("cpu-profile")
	agentDiag, unitDiags, compDiags, err := collectDiagnostics(ctx, streams, cpuProfile)
	if err != nil {
		return fmt.Errorf("failed collecting diagnostics: %w", err)
	}

	if err := diagnostics.ZipArchive(streams.Err, f, agentDiag, unitDiags, compDiags); err != nil {
		return fmt.Errorf("unable to create archive %q: %w", filepath, err)
	}
	fmt.Fprintf(streams.Out, "Created diagnostics archive %q\n", filepath)
	fmt.Fprintln(streams.Out, "***** WARNING *****\nCreated archive may contain plain text credentials.\nEnsure that files in archive are redacted before sharing.\n*******************")
	return nil
}

func collectDiagnostics(ctx context.Context, streams *cli.IOStreams, cpuProfile bool) ([]client.DiagnosticFileResult, []client.DiagnosticUnitResult, []client.DiagnosticComponentResult, error) {
	daemon := client.New()
	err := daemon.Connect(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer daemon.Disconnect()

	var additionalDiags []cproto.AdditionalDiagnosticRequest
	if cpuProfile {
		// console will just hang while we wait for the CPU profile; print something so user doesn't get confused
		fmt.Fprintf(streams.Out, "Creating diagnostics archive, waiting for CPU profile...\n")
		additionalDiags = []cproto.AdditionalDiagnosticRequest{cproto.AdditionalDiagnosticRequest_CPU}
	}

	agentDiag, err := daemon.DiagnosticAgent(ctx, additionalDiags)
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
		return nil, nil, nil, fmt.Errorf("no diags could be fetched")
	}

	return agentDiag, unitDiags, compDiags, nil
}

func createFile(filepath string) (*os.File, error) {
	// Ensure all the folders on filepath exist as os.Create does not do so.
	// 0777 is the same permission, before unmask, os.Create uses.
	dir := path.Dir(filepath)
	if err := os.MkdirAll(dir, 0777); err != nil {
		return nil, fmt.Errorf("could not create folders to save diagnostics on %q: %w",
			dir, err)
	}

	f, err := os.Create(filepath)
	if err != nil {
		return nil, fmt.Errorf("error creating .zip file: %w", err)
	}
	return f, nil
}
