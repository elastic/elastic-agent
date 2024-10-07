// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build darwin

package install

import (
	"context"
	"fmt"
	"os"

	"github.com/schollz/progressbar/v3"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func switchPlatformMode(pt *progressbar.ProgressBar, ownership utils.FileOwner) error {
	ctx := context.Background()

	unprivilegedVault, err := checkForUnprivilegedVault(ctx)
	if err != nil {
		return fmt.Errorf("error checking for unprivileged vault: %w", err)
	}
	if unprivilegedVault {
		if ownership.UID != 0 {
			// already has unprivileged vault and going into unprivileged mode (nothing to do)
			return nil
		}

		pt.Describe("Migrating the vault")

		// get the agent secret from the file vault
		var fileVaultOpts vault.Options
		vault.WithReadonly(true)(&fileVaultOpts)
		vault.WithVaultPath(paths.AgentVaultPath())(&fileVaultOpts)
		fileVault, err := vault.NewFileVault(ctx, fileVaultOpts)
		if err != nil {
			return fmt.Errorf("failed to open file vault: %w", err)
		}
		agentKey, err := fileVault.Get(ctx, secret.AgentSecretKey)
		if err != nil {
			return fmt.Errorf("failed to get agent secret from file vault: %w", err)
		}

		// set the agent secret into the keychain vault
		keychainVault, err := vault.NewDarwinKeyChainVault(ctx, vault.Options{})
		if err != nil {
			return fmt.Errorf("failed to open keychain vault: %w", err)
		}
		err = keychainVault.Set(ctx, secret.AgentSecretKey, agentKey)
		if err != nil {
			return fmt.Errorf("failed to set agent secret into keychain vault: %w", err)
		}

		// remove the file-based vault path
		err = os.Remove(paths.AgentVaultPath())
		if err != nil {
			return fmt.Errorf("failed to delete file vault: %w", err)
		}

		return nil
	}
	if ownership.UID == 0 {
		// already has privileged vault and going into privileged mode (nothing to do)
		return nil
	}

	pt.Describe("Migrating the vault")

	// get the agent secret from the keychain vault
	var keychainVaultOpts vault.Options
	vault.WithReadonly(true)(&keychainVaultOpts)
	keychainVault, err := vault.NewDarwinKeyChainVault(ctx, keychainVaultOpts)
	if err != nil {
		return fmt.Errorf("failed to open keychain vault: %w", err)
	}
	agentKey, err := keychainVault.Get(ctx, secret.AgentSecretKey)
	if err != nil {
		return fmt.Errorf("failed to get agent secret from keychain vault: %w", err)
	}

	// set the agent secret into the file vault
	var fileVaultOpts vault.Options
	vault.WithVaultPath(paths.AgentVaultPath())(&fileVaultOpts)
	fileVault, err := vault.NewFileVault(ctx, fileVaultOpts)
	if err != nil {
		return fmt.Errorf("failed to open file vault: %w", err)
	}
	err = fileVault.Set(ctx, secret.AgentSecretKey, agentKey)
	if err != nil {
		return fmt.Errorf("failed to set agent secret into file vault: %w", err)
	}

	// no need to set the permissions, that will be set in the next step of the switch operation

	return nil
}
