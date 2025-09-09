// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package watch

import (
	"context"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type upgradeAgentWatcher struct{}

func (a upgradeAgentWatcher) Watch(ctx context.Context, tilGrace, errorCheckInterval time.Duration, log *logp.Logger) error {
	return watch(ctx, tilGrace, errorCheckInterval, log)
}

type upgradeInstallationModifier struct{}

func (a upgradeInstallationModifier) Cleanup(log *logger.Logger, topDirPath, currentVersionedHome, currentHash string, removeMarker, keepLogs bool) error {
	return upgrade.Cleanup(log, topDirPath, currentVersionedHome, currentHash, removeMarker, keepLogs)
}

func (a upgradeInstallationModifier) Rollback(ctx context.Context, log *logger.Logger, c client.Client, topDirPath, prevVersionedHome, prevHash string) error {
	return upgrade.Rollback(ctx, log, c, topDirPath, prevVersionedHome, prevHash)
}
