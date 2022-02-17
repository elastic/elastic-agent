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

package application

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestMergeFleetConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"fleet": map[string]interface{}{
			"enabled":        true,
			"kibana":         map[string]interface{}{"host": "demo"},
			"access_api_key": "123",
		},
		"agent": map[string]interface{}{
			"grpc": map[string]interface{}{
				"port": uint16(6790),
			},
		},
	}

	rawConfig := config.MustNewConfigFrom(cfg)
	storage, conf, err := mergeFleetConfig(rawConfig)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.NotNil(t, conf)
	assert.Equal(t, conf.Fleet.Enabled, cfg["fleet"].(map[string]interface{})["enabled"])
	assert.Equal(t, conf.Fleet.AccessAPIKey, cfg["fleet"].(map[string]interface{})["access_api_key"])
	assert.Equal(t, conf.Settings.GRPC.Port, cfg["agent"].(map[string]interface{})["grpc"].(map[string]interface{})["port"].(uint16))
}
