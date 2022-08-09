package cmd

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/testing/poc"
	"github.com/stretchr/testify/assert"
)

func TestDiagnostics(t *testing.T) {
	poc.ElasticAgentUp()
	//err, identifier := poc.StackUp()
	//defer poc.StackDown(identifier)

	//assert.NoError(t, err)
	//assert.NotNil(t, identifier)
	rootDir := poc.ElasticAgentDirectory("")
	paths.ConfigFilePath = filepath.Join(rootDir, "_meta", paths.DefaultConfigName)
	streams := cli.NewIOStreams()
	cmd := newDiagnosticsCommand(os.Args, streams)
	output, _ := poc.ExecuteCommand(cmd)
	assert.Equal(t, "test", output)

}

func ElasticAgentUp() error {
	rootDir := poc.ElasticAgentDirectory("")
	paths.ConfigFilePath = filepath.Join(rootDir, "_meta", paths.DefaultConfigName)
	streams := cli.NewIOStreams()
	cmd := newRunCommandWithArgs(os.Args, streams)
	output, _ := poc.ExecuteCommand(cmd)
	_ = output
	return nil
}

func TestAgent1(t *testing.T) {
	rootDir := poc.ElasticAgentDirectory("")
	paths.ConfigFilePath = filepath.Join(rootDir, "_meta", paths.DefaultConfigName)
	t.Run("test agent with subcommand", func(t *testing.T) {
		streams, _, _, _ := cli.NewTestingIOStreams()
		cmd := NewCommandWithArgs([]string{}, streams)
		cmd.SetOutput(streams.Out)
		cmd.Execute()
	})

	t.Run("test run subcommand", func(t *testing.T) {

		streams, _, out, _ := cli.NewTestingIOStreams()
		cmd := newRunCommandWithArgs([]string{}, streams)
		cmd.SetOut(streams.Out)
		go cmd.Execute()
		contents, err := ioutil.ReadAll(out)
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, strings.Contains(string(contents), "Hello I am running"))
	})
	t.Run("test diag subcommand", func(t *testing.T) {

		streams, _, out, _ := cli.NewTestingIOStreams()
		cmd := newDiagnosticsCommand([]string{}, streams)
		cmd.SetOut(streams.Out)
		cmd.Execute()
		contents, err := ioutil.ReadAll(out)
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, strings.Contains(string(contents), "Hello I am running"))
	})
}
