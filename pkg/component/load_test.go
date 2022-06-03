// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadSpec_Components(t *testing.T) {
	scenarios := []struct {
		Name string
		Path string
	}{
		{
			Name: "APM Server",
			Path: "apm-server.yml",
		},
		{
			Name: "Auditbeat",
			Path: "auditbeat.yml",
		},
		{
			Name: "Cloudbeat",
			Path: "cloudbeat.yml",
		},
		{
			Name: "Endpoint Security",
			Path: "endpoint-security.yml",
		},
		{
			Name: "Filebeat",
			Path: "filebeat.yml",
		},
		{
			Name: "Fleet Server",
			Path: "fleet-server.yml",
		},
		{
			Name: "Heartbeat",
			Path: "heartbeat.yml",
		},
		{
			Name: "Metricbeat",
			Path: "metricbeat.yml",
		},
		{
			Name: "Osquerybeat",
			Path: "osquerybeat.yml",
		},
		{
			Name: "Packetbeat",
			Path: "packetbeat.yml",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			data, err := ioutil.ReadFile(filepath.Join("..", "..", "specs", scenario.Path))
			require.NoError(t, err)
			_, err = LoadSpec(data)
			require.NoError(t, err)
		})
	}
}
