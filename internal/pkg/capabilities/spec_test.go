// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestUnmarshal(t *testing.T) {

	t.Run("valid yaml", func(t *testing.T) {
		rr := &capabilitiesSpec{}

		err := yaml.Unmarshal(yamlDefinitionValid, &rr)
		assert.Nil(t, err, "no error is expected")

		// The yaml has one capability of each type
		assert.Equal(t, 1, len(rr.Capabilities.inputChecks))
		assert.Equal(t, 1, len(rr.Capabilities.outputChecks))
		assert.Equal(t, 1, len(rr.Capabilities.upgradeChecks))
	})

	t.Run("invalid yaml", func(t *testing.T) {
		var rr capabilitiesSpec

		err := yaml.Unmarshal(yamlDefinitionInvalid, &rr)

		assert.Error(t, err, "error is expected")
	})
}

var yamlDefinitionValid = []byte(`capabilities:
-
  rule: "allow"
  upgrade: "${version} == '8.0.0'"
-
  input: "system/metrics"
  rule: "allow"
-
  output: "elasticsearch"
  rule: "allow"
`)

var yamlDefinitionInvalid = []byte(`
capabilities:
-
  rule: allow
  upgrade: "${version} == '8.0.0'"
-
  input: "system/metrics"
  rule: allow
-
  output: elasticsearch
  rule: allow
-
  ayay: elasticsearch
  rule: allow
`)
