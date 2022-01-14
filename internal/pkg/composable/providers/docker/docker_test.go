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

package docker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/common/bus"
	"github.com/elastic/beats/v7/libbeat/common/docker"
)

func TestGenerateData(t *testing.T) {
	container := &docker.Container{
		ID:   "abc",
		Name: "foobar",
		Labels: map[string]string{
			"do.not.include":          "true",
			"co.elastic.logs/disable": "true",
		},
	}
	event := bus.Event{
		"container": container,
	}

	data, err := generateData(event)
	require.NoError(t, err)
	mapping := map[string]interface{}{
		"container": map[string]interface{}{
			"id":    container.ID,
			"name":  container.Name,
			"image": container.Image,
			"labels": common.MapStr{
				"do": common.MapStr{"not": common.MapStr{"include": "true"}},
				"co": common.MapStr{"elastic": common.MapStr{"logs/disable": "true"}},
			},
		},
	}
	processors := []map[string]interface{}{
		{
			"add_fields": map[string]interface{}{
				"fields": map[string]interface{}{
					"id":    container.ID,
					"name":  container.Name,
					"image": container.Image,
					"labels": common.MapStr{
						"do_not_include":          "true",
						"co_elastic_logs/disable": "true",
					},
				},
				"to": "container",
			},
		},
	}

	assert.Equal(t, container, data.container)
	assert.Equal(t, mapping, data.mapping)
	assert.Equal(t, processors, data.processors)
}
