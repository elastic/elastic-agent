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

func TestEnrollCmd(t *testing.T) {
	err, identifier := poc.StackUp()
	defer poc.StackDown(identifier)

	assert.NoError(t, err)
	assert.NotNil(t, identifier)
	rootDir := poc.ElasticAgentDirectory("")
	paths.ConfigFilePath = filepath.Join(rootDir, "_meta", paths.DefaultConfigName)
	streams, _, out, _ := cli.NewTestingIOStreams()
	cmd := newEnrollCommandWithArgs(os.Args, streams)
	cmd.Flags().Set("url", "https://localhost:8220")
	enrollment, err := poc.CreateEnrollmentAPIKey()
	assert.NoError(t, err)
	cmd.Flags().Set("enrollment-token", enrollment)
	cmd.Flags().Set("insecure", "true")
	cmd.Flags().Set("force", "true")
	if !assert.NoError(t, err) {
		return
	}
	cmd.SetOut(streams.Out)
	err = cmd.Execute()
	if !assert.NoError(t, err) {
		return
	}
	contents, err := ioutil.ReadAll(out)
	if !assert.NoError(t, err) {
		return
	}
	assert.True(t, strings.Contains(string(contents), "Successfully enrolled the Elastic Agent."))

}
