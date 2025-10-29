// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type RollbackHook func(ctx context.Context, log *logger.Logger, topDirPath string) error

type RollbackOptionSetter interface {
	SetSkipCleanup(skipCleanup bool)
	SetSkipRestart(skipRestart bool)
	SetPreRestartHook(preRestartHook RollbackHook)
	SetRemoveMarker(removeMarker bool)
}

type RollbackOption func(ros RollbackOptionSetter)
