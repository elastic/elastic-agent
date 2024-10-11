// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package vault

import (
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

type OptionFunc func(o *Options)

type CommonVaultOptions struct {
	readonly     bool
	unprivileged bool
}

type FileVaultOptions struct {
	vaultPath      string
	lockRetryDelay time.Duration
	ownership      utils.FileOwner
}

type KeychainVaultOptions struct {
	entryName string
}

type Options struct {
	CommonVaultOptions
	FileVaultOptions
	KeychainVaultOptions
}

// WithReadonly opens storage for read-only access only, noop for Darwin
func WithReadonly(readonly bool) OptionFunc {
	return func(o *Options) {
		o.readonly = readonly
	}
}

// WithVaultPath allows to specify the vault path for the file-based vault implementation (doesn't apply for the keychain vault)
func WithVaultPath(vaultPath string) OptionFunc {
	return func(o *Options) {
		o.vaultPath = vaultPath
	}
}

// WithVaultOwnership allows to specify the ownership that should apply for the file-based vault implementation (doesn't apply for the keychain vault)
func WithVaultOwnership(ownership utils.FileOwner) OptionFunc {
	return func(o *Options) {
		o.ownership = ownership
	}
}

// WithVaultEntryName allows to specify the vault key entry name in the keychain (it applies only for keychain vault on darwin)
func WithVaultEntryName(entryName string) OptionFunc {
	return func(o *Options) {
		o.entryName = entryName
	}
}

// WithUnprivileged creates an unprivileged vault, has an effect only on Darwin
func WithUnprivileged(unprivileged bool) OptionFunc {
	return func(o *Options) {
		o.unprivileged = unprivileged
	}
}

// ApplyOptions applies options for Windows, Linux and Mac, not all the options may be used
func ApplyOptions(opts ...OptionFunc) (Options, error) {
	ownership, err := utils.CurrentFileOwner()
	if err != nil {
		return Options{}, fmt.Errorf("failed to get current file owner: %w", err)
	}
	o := Options{
		CommonVaultOptions: CommonVaultOptions{
			readonly:     false,
			unprivileged: false,
		},
		FileVaultOptions: FileVaultOptions{
			vaultPath:      paths.AgentVaultPath(),
			lockRetryDelay: defaultFlockRetryDelay,
			ownership:      ownership,
		},
		KeychainVaultOptions: KeychainVaultOptions{
			entryName: paths.AgentKeychainName(),
		},
	}

	for _, opt := range opts {
		opt(&o)
	}
	return o, nil
}
