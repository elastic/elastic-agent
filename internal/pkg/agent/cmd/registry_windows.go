// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func newWindowsCommandWithArgs(_ []string, _ *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Hidden: true,
		Use:    "windows",
		Short:  "Windows-specific subcommands",
	}

	registry := &cobra.Command{
		Use:   "registry",
		Short: "Manage the Elastic Agent Windows registry entries",
	}

	registry.AddCommand(newWindowsRegistryUpdateCommandWithArgs())
	cmd.AddCommand(registry)
	return cmd
}

func newWindowsRegistryUpdateCommandWithArgs() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update the Elastic Agent Windows Add/Remove Programs registry entry",
		Long: `Creates or updates the Elastic Agent entry in the Windows Add/Remove Programs list
and configures the registry key ACL so unprivileged upgrades can update it automatically.

This is typically needed once after upgrading from a version before 9.4.0 in unprivileged mode.`,
		Args: cobra.ExactArgs(0),
		Run: func(c *cobra.Command, args []string) {
			if err := windowsRegistryUpdateCmd(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n%s\n", err, troubleshootMessage)
				os.Exit(1)
			}
		},
	}
}

func windowsRegistryUpdateCmd() error {
	isAdmin, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("unable to perform windows registry update while checking for Administrator rights: %w", err)
	}
	if !isAdmin {
		return fmt.Errorf("unable to perform windows registry update, not executed with %s permissions", utils.PermissionUser)
	}

	topPath := paths.Top()

	if err := install.UpsertUninstallEntry(topPath, release.VersionWithSnapshot()); err != nil {
		return fmt.Errorf("failed to update registry entry: %w", err)
	}

	// configure the ACL so the elastic-agent-user can update the entry on future unprivileged upgrades;
	// this is a recovery path for agents upgraded from pre-9.4.0 where the ACL was never set
	var ownership utils.FileOwner
	if uid, err := install.FindUID(install.ElasticUsername); err == nil {
		ownership.UID = uid
	}
	if err := install.ConfigureRegistryPermissions(ownership); err != nil {
		return fmt.Errorf("failed to configure registry permissions: %w", err)
	}

	// remove stale MSI entries that may have been left by an earlier MSI installation
	if err := install.RemoveMSIUninstallEntries(); err != nil {
		return fmt.Errorf("failed to remove MSI uninstall registry entries: %w", err)
	}

	return nil
}
