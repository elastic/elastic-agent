// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package handlers

import (
	"io"
	"time"

	"github.com/elastic/elastic-agent-libs/file"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
)

const saveRetryInterval = 50 * time.Millisecond
const saveRetryDuration = 2 * time.Second

// saveConfigToStore saves the given configuration (reader) to the given store.
// On Windows platforms, the save operation is retried if the error is an
// ACCESS_DENIED error, which can happen if the file is locked by another process.
func saveConfigToStore(store storage.Store, reader io.Reader) error {
	return store.Save(reader, file.WithRenameRetries(saveRetryDuration, saveRetryInterval))
}
