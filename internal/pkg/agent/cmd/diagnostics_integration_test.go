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

func TestElasticAgentDiagnostics(t *testing.T) {
	rootDir := poc.ElasticAgentDirectory("")
	paths.ConfigFilePath = filepath.Join(rootDir, "_meta", paths.DefaultConfigName)
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
		cmd := newDiagnosticsCommand(os.Args, streams)
		cmd.SetOut(streams.Out)
		err := cmd.Execute()
		if !assert.NoError(t, err) {
			return
		}
		contents, err := ioutil.ReadAll(out)
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, strings.Contains(string(contents), "Hello I am running"))
	})
}
