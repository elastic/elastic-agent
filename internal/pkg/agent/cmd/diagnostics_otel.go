// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
)

func newOtelDiagnosticsCommand(streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diagnostics",
		Short: "Gather diagnostics information from the EDOT and write it to a zip archive",
		Long:  "This command gathers diagnostics information from the EDOT and writes it to a zip archive",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := otelDiagnosticCmd(streams, cmd); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().StringP("file", "f", "", "name of the output diagnostics zip archive")
	return cmd
}

func otelDiagnosticCmd(streams *cli.IOStreams, cmd *cobra.Command) error {
	resp, err := otel.PerformDiagnosticsExt(cmd.Context())
	if err != nil {
		return fmt.Errorf("failed to get edot diagnostics: %v", err)
	}

	agentDiag := make([]client.DiagnosticFileResult, 0)
	for _, r := range resp.GlobalDiagnostics {
		agentDiag = append(agentDiag, client.DiagnosticFileResult{
			Name:        r.Name,
			Filename:    r.Filename,
			ContentType: r.ContentType,
			Content:     r.Content,
			Description: r.Description,
		})
	}

	componentDiag := make([]client.DiagnosticComponentResult, 0)
	for _, r := range resp.ComponentDiagnostics {
		res := client.DiagnosticComponentResult{
			Results: make([]client.DiagnosticFileResult, 0),
		}
		res.Results = append(res.Results, client.DiagnosticFileResult{
			Name:        r.Name,
			Filename:    r.Filename,
			ContentType: r.ContentType,
			Content:     r.Content,
			Description: r.Description,
		})
		res.ComponentID = r.Name
		componentDiag = append(componentDiag, res)
	}

	filepath, _ := cmd.Flags().GetString("file")
	if filepath == "" {
		ts := time.Now().UTC()
		filepath = "edot-diagnostics-" + ts.Format("2006-01-02T15-04-05Z07-00") + ".zip" // RFC3339 format that replaces : with -, so it will work on Windows
	}
	f, err := createFile(filepath)
	if err != nil {
		return fmt.Errorf("could not create diagnostics file %q: %w", filepath, err)
	}
	defer f.Close()

	return diagnostics.ZipArchive(streams.Err, f, paths.Top(), agentDiag, nil, componentDiag, false)
}
