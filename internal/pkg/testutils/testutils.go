// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testutils

import (
	"runtime"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
)

func InitStorage(t *testing.T) {
	storage.DisableEncryptionDarwin()
	if runtime.GOOS != "darwin" {
		err := secret.CreateAgentSecret()
		if err != nil {
			t.Fatal(err)
		}
	}
}
