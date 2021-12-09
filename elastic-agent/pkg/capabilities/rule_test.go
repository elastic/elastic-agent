// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package capabilities

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestUnmarshal(t *testing.T) {
	t.Run("valid json", func(t *testing.T) {
		rr := &ruleDefinitions{Capabilities: make([]ruler, 0)}

		err := json.Unmarshal(jsonDefinitionValid, &rr)

		assert.Nil(t, err, "no error is expected")
		assert.Equal(t, 3, len(rr.Capabilities))
		assert.Equal(t, "*capabilities.upgradeCapability", reflect.TypeOf(rr.Capabilities[0]).String())
		assert.Equal(t, "*capabilities.inputCapability", reflect.TypeOf(rr.Capabilities[1]).String())
		assert.Equal(t, "*capabilities.outputCapability", reflect.TypeOf(rr.Capabilities[2]).String())
	})

	t.Run("invalid json", func(t *testing.T) {
		var rr ruleDefinitions

		err := json.Unmarshal(jsonDefinitionInvalid, &rr)

		assert.Error(t, err, "error is expected")
	})

	t.Run("valid yaml", func(t *testing.T) {
		rr := &ruleDefinitions{Capabilities: make([]ruler, 0)}

		err := yaml.Unmarshal(yamlDefinitionValid, &rr)

		assert.Nil(t, err, "no error is expected")
		assert.Equal(t, 3, len(rr.Capabilities))
		assert.Equal(t, "*capabilities.upgradeCapability", reflect.TypeOf(rr.Capabilities[0]).String())
		assert.Equal(t, "*capabilities.inputCapability", reflect.TypeOf(rr.Capabilities[1]).String())
		assert.Equal(t, "*capabilities.outputCapability", reflect.TypeOf(rr.Capabilities[2]).String())
	})

	t.Run("invalid yaml", func(t *testing.T) {
		var rr ruleDefinitions

		err := yaml.Unmarshal(yamlDefinitionInvalid, &rr)

		assert.Error(t, err, "error is expected")
	})
}

var jsonDefinitionValid = []byte(`{
"capabilities": [
	{
		"upgrade": "${version} == '8.0.0'",
		"rule": "allow"
	},
	{
		"input": "system/metrics",
		"rule": "allow"
	},
	{
		"output": "elasticsearch",
		"rule": "allow"
	}
]
}`)

var jsonDefinitionInvalid = []byte(`{
"capabilities": [
	{
	"upgrade": "${version} == '8.0.0'",
	"rule": "allow"
},
{
	"input": "system/metrics",
	"rule": "allow"
},
{
	"output": "elasticsearch",
	"rule": "allow"
},
{
	"ayay": "elasticsearch",
	"rule": "allow"
}
]
}`)

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
