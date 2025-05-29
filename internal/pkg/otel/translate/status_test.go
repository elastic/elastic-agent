// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// Tests for status.go

func TestParseEntityStatusId(t *testing.T) {
	tests := []struct {
		id               string
		expectedKind     string
		expectedEntityID string
	}{
		{"pipeline:logs", "pipeline", "logs"},
		{"pipeline:logs/filestream-monitoring", "pipeline", "logs/filestream-monitoring"},
		{"receiver:filebeat/filestream-monitoring", "receiver", "filebeat/filestream-monitoring"},
		{"exporter:elasticsearch/default", "exporter", "elasticsearch/default"},
		{"invalid", "", ""},
	}

	for _, test := range tests {
		componentKind, pipelineId := parseEntityStatusId(test.id)
		assert.Equal(t, test.expectedKind, componentKind, "component kind")
		assert.Equal(t, test.expectedEntityID, pipelineId, "pipeline id")
	}
}
