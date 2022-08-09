package cmd

import (
	"os"
	"path/filepath"
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
	streams := cli.NewIOStreams()
	cmd := newEnrollCommandWithArgs(os.Args, streams)
	cmd.Flags().Set("url", "https://localhost:8220")
	enrollment, err := poc.CreateEnrollmentAPIKey()
	assert.NoError(t, err)
	cmd.Flags().Set("enrollment-token", enrollment)
	cmd.Flags().Set("insecure", "true")
	assert.NoError(t, err)

	output, _ := poc.ExecuteCommand(cmd)
	assert.Equal(t, "test", output)

}
