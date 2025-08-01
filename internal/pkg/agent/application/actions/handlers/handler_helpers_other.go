// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package handlers

import (
	"io"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
)

// On non-Windows platforms, save operations are not retried
// upon error.
func checkSaveErrorAndRetry(_ error, _ storage.Store, _ io.Reader) bool {
	return false
}
