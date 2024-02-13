// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package info

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestInjectAgentConfig(t *testing.T) {
	c := config.New()
	err := InjectAgentConfig(c)
	assert.NoError(t, err)
}

func TestAgentGlobalConfig(t *testing.T) {
	c, err := agentGlobalConfig()
	assert.NoError(t, err)
	assert.NotEmpty(t, c)
}
