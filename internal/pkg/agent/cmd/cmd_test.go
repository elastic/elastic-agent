// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestAgent(t *testing.T) {
	// t.Run("test agent with subcommand", func(t *testing.T) {
	// 	streams, _, _, _ := cli.NewTestingIOStreams()
	// 	cmd := NewCommandWithArgs([]string{}, streams)
	// 	cmd.SetOutput(streams.Out)
	// 	cmd.Execute()
	// })

	// t.Run("test run subcommand", func(t *testing.T) {
	// 	streams, _, out, _ := cli.NewTestingIOStreams()
	// 	cmd := newRunCommandWithArgs(globalFlags{
	// 		PathConfigFile: filepath.Join("build", "elastic-agent.yml"),
	// 	}, []string{}, streams)
	// 	cmd.SetOutput(streams.Out)
	// 	cmd.Execute()
	// 	contents, err := ioutil.ReadAll(out)
	// 	if !assert.NoError(t, err) {
	// 		return
	// 	}
	// 	assert.True(t, strings.Contains(string(contents), "Hello I am running"))
	// })
}

func TestAddCommandIfNotNil(t *testing.T) {
	cmd := &cobra.Command{}

	parent := &cobra.Command{}
	addCommandIfNotNil(parent, cmd)
	require.Equal(t, 1, len(parent.Commands()))

	parent = &cobra.Command{}
	addCommandIfNotNil(parent, nil)
	require.Equal(t, 0, len(parent.Commands()))

	// this should not panic
	addCommandIfNotNil(nil, cmd)
}
