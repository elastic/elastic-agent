// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Option is a functional option for Upgrader.Upgrade.
type Option func(*upgradeOptions)

type upgradeOptions struct {
	// preSymlinkCallback is invoked just before changeSymlink, after all go/no-go
	// checks have passed. This is where components like endpoint-security should be
	// notified to drop tamper protection, since at this point the upgrade is
	// committed to completing.
	preSymlinkCallback func(ctx context.Context, log *logger.Logger, action *fleetapi.ActionUpgrade) error
}

// WithPreSymlinkCallback registers a callback to be called just before the
// symlink is switched to the new agent binary, after all upgrade viability
// checks (same-version guard, artifact download, signature verification, and
// package validation) have passed.
func WithPreSymlinkCallback(fn func(ctx context.Context, log *logger.Logger, action *fleetapi.ActionUpgrade) error) Option {
	return func(o *upgradeOptions) {
		o.preSymlinkCallback = fn
	}
}

// InvokePreSymlinkCallback resolves opts and calls the preSymlinkCallback if one
// is registered. Returns nil when no callback is set or when the callback
// succeeds. Implementations of UpgradeManager (typically test fakes) can use
// this to honor the pre-symlink callback contract without knowing about the
// internal upgradeOptions type.
func InvokePreSymlinkCallback(opts []Option, ctx context.Context, log *logger.Logger, action *fleetapi.ActionUpgrade) error {
	var uOpts upgradeOptions
	for _, opt := range opts {
		opt(&uOpts)
	}
	if uOpts.preSymlinkCallback != nil {
		return uOpts.preSymlinkCallback(ctx, log, action)
	}
	return nil
}
