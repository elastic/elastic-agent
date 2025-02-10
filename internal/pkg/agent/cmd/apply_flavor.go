// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
)

func newApplyFlavorCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply-flavor",
		Short: "Apply Flavor cleans up unnecessary components from agent installation directory",
		Run: func(c *cobra.Command, _ []string) {
			if err := applyCmd(); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				logExternal(fmt.Sprintf("%s apply flavor failed: %s", paths.BinaryName, err))
				os.Exit(1)
			}
		},
		Hidden: true,
	}

	return cmd
}

func applyCmd() error {
	topPath := paths.Top()
	detectedFlavor, err := install.UsedFlavor(topPath, "")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if detectedFlavor == "" {
		return nil
	}

	versionedHome := paths.VersionedHome(topPath)
	manifestFilePath := filepath.Join(versionedHome, v1.ManifestFileName)
	flavor, err := install.Flavor(detectedFlavor, manifestFilePath, nil)
	if err != nil {
		return err
	}

	return install.ApplyFlavor(versionedHome, flavor)
}
