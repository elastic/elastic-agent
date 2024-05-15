// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"

	"github.com/elastic/elastic-agent-libs/logp"
)

// logLevelSetter interface represents an actor able to set the global log level in agent
type logLevelSetter interface {
	SetLogLevel(ctx context.Context, lvl *logp.Level) error
}
