// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type collectorExecution interface {
	startCollector(ctx context.Context, logger *logger.Logger, cfg *confmap.Conf, errCh chan error, statusCh chan *status.AggregateStatus) (collectorHandle, error)
}

type collectorHandle interface {
	Stop(waitTime time.Duration)
}
