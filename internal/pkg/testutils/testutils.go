// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testutils

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
)

// InitStorage prepares storage for testing.
// disabled on Darwin.
func InitStorage(t *testing.T) {
	storage.DisableEncryptionDarwin()
	if runtime.GOOS != "darwin" {
		err := secret.CreateAgentSecret(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	}
}

// NewErrorLogger creates an error logger for testing.
func NewErrorLogger(t *testing.T) *logger.Logger {
	t.Helper()

	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.ErrorLevel

	log, err := logger.NewFromConfig("", loggerCfg, false)
	require.NoError(t, err)
	return log
}
