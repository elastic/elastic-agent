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

package localdynamic

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/composable"
	ctesting "github.com/elastic/elastic-agent-poc/elastic-agent/pkg/composable/testing"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/config"
)

func TestContextProvider(t *testing.T) {
	mapping1 := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}
	processors1 := []map[string]interface{}{
		{
			"add_fields": map[string]interface{}{
				"fields": map[string]interface{}{
					"add": "value1",
				},
				"to": "dynamic",
			},
		},
	}
	mapping2 := map[string]interface{}{
		"key1": "value12",
		"key2": "value22",
	}
	processors2 := []map[string]interface{}{
		{
			"add_fields": map[string]interface{}{
				"fields": map[string]interface{}{
					"add": "value12",
				},
				"to": "dynamic",
			},
		},
	}
	mapping := []map[string]interface{}{
		{
			"vars":       mapping1,
			"processors": processors1,
		},
		{
			"vars":       mapping2,
			"processors": processors2,
		},
	}
	cfg, err := config.NewConfigFrom(map[string]interface{}{
		"items": mapping,
	})
	require.NoError(t, err)
	builder, _ := composable.Providers.GetDynamicProvider("local_dynamic")
	provider, err := builder(nil, cfg)
	require.NoError(t, err)

	comm := ctesting.NewDynamicComm(context.Background())
	err = provider.Run(comm)
	require.NoError(t, err)

	curr1, ok1 := comm.Current("0")
	assert.True(t, ok1)
	assert.Equal(t, ItemPriority, curr1.Priority)
	assert.Equal(t, mapping1, curr1.Mapping)
	assert.Equal(t, processors1, curr1.Processors)

	curr2, ok2 := comm.Current("1")
	assert.True(t, ok2)
	assert.Equal(t, ItemPriority, curr2.Priority)
	assert.Equal(t, mapping2, curr2.Mapping)
	assert.Equal(t, processors2, curr2.Processors)
}
