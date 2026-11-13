// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/workflowrunner"
	"github.com/elastic/elastic-agent/pkg/component"
)

func TestSpecLoads(t *testing.T) {
	data, err := os.ReadFile("workflow-runner.spec.yml")
	require.NoError(t, err)

	spec, err := component.LoadSpec(data)
	require.NoError(t, err)
	require.Len(t, spec.Inputs, 1)
	assert.Equal(t, workflowrunner.ActionName, spec.Inputs[0].Name)
	assert.Equal(t, []string{"elasticsearch"}, spec.Inputs[0].Outputs)
	require.NotNil(t, spec.Inputs[0].AckActionData, "acks must not echo the request")
	assert.ElementsMatch(t, []string{"space_id", "execution_id", "step_id"}, spec.Inputs[0].AckActionData.Fields)
}

func TestDataPath(t *testing.T) {
	got, err := dataPath([]string{"-E", "logging.level=info", "-E", "path.data=/opt/agent/run/workflow-http-default"})
	require.NoError(t, err)
	assert.Equal(t, "/opt/agent/run/workflow-http-default", got)

	got, err = dataPath([]string{"-Epath.data=/tmp/joined"})
	require.NoError(t, err)
	assert.Equal(t, "/tmp/joined", got)

	wd, err := os.Getwd()
	require.NoError(t, err)
	got, err = dataPath(nil)
	require.NoError(t, err)
	assert.Equal(t, wd, got)
}
