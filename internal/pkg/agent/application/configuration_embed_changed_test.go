// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

// This test exists to notify the cloudbeat team in case the default agent fleet config is changed.
func TestDefaultAgentFleetConfig(t *testing.T) {
	cfg := map[string]interface{}{}

	err := yaml.Unmarshal(DefaultAgentFleetConfig, &cfg)
	assert.NoError(t, err)

	assert.Equal(t, map[string]interface{}{"fleet": map[interface{}]interface{}{"enabled": true}}, cfg)
}
