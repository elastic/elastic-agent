// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func newEncryptConfig(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encrypt-config",
		Short: "Encrypt elastic-agent config",
		Long:  "This command encrypts the plain-test elastic-agent config file and stores the results in the home directory.",
		Run: func(c *cobra.Command, args []string) {
			if err := encryptConfigCmd(streams, c); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolP("force", "f", false, "force bypasses checks and forces the input config to be encrypted")

	return cmd
}

func encryptConfigCmd(streams *cli.IOStreams, cmd *cobra.Command) error {
	force, _ := cmd.Flags().GetBool("force")

	if !force {
		if err := checkInputIsStandalone(paths.ConfigFile()); err != nil {
			return err
		}
		if err := checkExistingEnc(paths.AgentConfigFile()); err != nil {
			return err
		}
	}

	// prepare secret so we can encrypt
	isRoot, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("failed to check for root/Administrator privileges: %w", err)
	}
	err = secret.CreateAgentSecret(context.Background(), vault.WithUnprivileged(!isRoot))
	if err != nil {
		return fmt.Errorf("failed to read/write secrets: %w", err)
	}

	err = encryptConfig(streams, paths.ConfigFile(), paths.AgentConfigFile())
	if err != nil {
		return fmt.Errorf("failed to encrypt config: %w", err)
	}
	return nil
}

// checkInputIsStandalone ensure the input file is not managed by fleet.
func checkInputIsStandalone(sourceFile string) error {
	rawConfig, err := config.LoadFile(sourceFile)
	if err != nil {
		return fmt.Errorf("unable to load config file: %w", err)
	}
	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return fmt.Errorf("unable to load config: %w", err)
	}

	// Check if config file indicates it is fleet-managed.
	if !configuration.IsStandalone(cfg.Fleet) {
		return errors.New("input config file is managed by fleet")
	}
	return nil
}

// checkExistingEnc checks if existing encryped config exists, and is associated with fleet.
// Returns an error if fleet-config is detected.
// Does not return an error if no encrypted config file exists.
func checkExistingEnc(sourceFile string, opts ...storage.EncryptedOptionFunc) error {
	_, err := os.Stat(sourceFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("unable to stat local encrypted file: %w", err)
	}
	store, err := storage.NewEncryptedDiskStore(context.Background(), sourceFile, opts...)
	if err != nil {
		return fmt.Errorf("unable to create encrypted file storage: %w", err)
	}
	reader, err := store.Load()
	if err != nil {
		return fmt.Errorf("unable to load encrypted file: %w", err)
	}
	encConfig, err := config.NewConfigFrom(reader)
	if err != nil {
		return fmt.Errorf("unable to read encrypted config file: %w", err)
	}
	cfg, err := configuration.NewFromConfig(encConfig)
	if err != nil {
		return fmt.Errorf("unable to parse encryted config file as configuration: %w", err)
	}
	if !configuration.IsStandalone(cfg.Fleet) {
		return errors.New("encrypted config file indicates fleet management")
	}
	return nil
}

// encryptConfig reads the file from sourcePath and writes the encrypted results to destPath.
func encryptConfig(streams *cli.IOStreams, sourcePath, destPath string, opts ...storage.EncryptedOptionFunc) error {
	_, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	sourceStore, err := storage.NewDiskStore(sourcePath)
	if err != nil {
		// Instantiating a disk store should never return an error
		return fmt.Errorf("failed to instantiate encryption source: %w", err)
	}
	sourceReader, err := sourceStore.Load()
	if err != nil {
		return fmt.Errorf("failed to load encryption source: %w", err)
	}
	defer func() {
		if err := sourceReader.Close(); err != nil {
			fmt.Fprintf(streams.Err, "Error: failure closing encryption source: %v\n", err)
		}
	}()

	destStore, err := storage.NewEncryptedDiskStore(context.Background(), destPath, opts...)
	if err != nil {
		return fmt.Errorf("failed to instantiate encryption destination: %w", err)
	}
	err = destStore.Save(sourceReader)
	if err != nil {
		return fmt.Errorf("failed to encrypt config: %w", err)
	}
	fmt.Fprintf(streams.Out, "encrypted config source=%s dest=%s\n", sourcePath, destPath)
	return nil
}
