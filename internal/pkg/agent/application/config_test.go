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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestConfig(t *testing.T) {
	testMgmtMode(t)
	testLocalConfig(t)
}

func testMgmtMode(t *testing.T) {
	t.Run("succeed when local mode is selected", func(t *testing.T) {
		c := mustWithConfigMode(true)
		m := localConfig{}
		err := c.Unpack(&m)
		require.NoError(t, err)
		assert.Equal(t, false, m.Fleet.Enabled)
		assert.Equal(t, true, configuration.IsStandalone(m.Fleet))

	})

	t.Run("succeed when fleet mode is selected", func(t *testing.T) {
		c := mustWithConfigMode(false)
		m := localConfig{}
		err := c.Unpack(&m)
		require.NoError(t, err)
		assert.Equal(t, true, m.Fleet.Enabled)
		assert.Equal(t, false, configuration.IsStandalone(m.Fleet))
	})
}

func testLocalConfig(t *testing.T) {
	t.Run("only accept positive period", func(t *testing.T) {
		c := config.MustNewConfigFrom(map[string]interface{}{
			"enabled": true,
			"period":  0,
		})

		m := configuration.ReloadConfig{}
		err := c.Unpack(&m)
		assert.Error(t, err)

		c = config.MustNewConfigFrom(map[string]interface{}{
			"enabled": true,
			"period":  1,
		})

		err = c.Unpack(&m)
		assert.NoError(t, err)
		assert.Equal(t, 1*time.Second, m.Period)
	})
}

func mustWithConfigMode(standalone bool) *config.Config {
	return config.MustNewConfigFrom(
		map[string]interface{}{
			"fleet": map[string]interface{}{
				"enabled":        !standalone,
				"kibana":         map[string]interface{}{"host": "demo"},
				"access_api_key": "123",
			},
		},
	)
}
