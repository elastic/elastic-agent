// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package handlers

import (
	"io"

	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
)

// saveConfigToStore saves the given configuration (reader) to the given store
func saveConfigToStore(store storage.Store, reader io.Reader, _ *logger.Logger) error {
	return store.Save(reader)
}
