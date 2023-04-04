// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package docker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-autodiscover/bus"
	"github.com/elastic/elastic-agent-autodiscover/docker"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func TestGenerateData(t *testing.T) {
	container := &docker.Container{
		ID:    "abc",
		Name:  "foobar",
		Image: "busybox:latest",
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
			"id":   container.ID,
			"name": container.Name,
			"image": map[string]interface{}{
				"name": container.Image,
			},
			"labels": mapstr.M{
				"do": mapstr.M{"not": mapstr.M{"include": "true"}},
				"co": mapstr.M{"elastic": mapstr.M{"logs/disable": "true"}},
			},
		},
	}
	processors := []map[string]interface{}{
		{
			"add_fields": map[string]interface{}{
				"fields": map[string]interface{}{
					"id":         container.ID,
					"name":       container.Name,
					"image.name": container.Image,
					"labels": mapstr.M{
						"do_not_include":          "true",
						"co_elastic_logs/disable": "true",
					},
				},
				"target": "container",
			},
		},
	}

	assert.Equal(t, container, data.container)
	assert.Equal(t, mapping, data.mapping)
	assert.Equal(t, processors, data.processors)
}
