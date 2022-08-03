//go:build integration
// +build integration

package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestDiagnostics(t *testing.T) {
	//err, identifier := stackUp()
	//if err != nil {
	//	panic(err)
	//}
	//assert.NoError(t, err)
	//assert.NotNil(t, identifier)
	//cmd := NewCommand()
	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	pwd = filepath.Dir(pwd)
	pwd = filepath.Dir(pwd)
	pwd = filepath.Dir(pwd)
	pwd = filepath.Dir(pwd)
	hel := filepath.Join(pwd, "build")
	fmt.Println(hel)
	paths.SetConfig(hel)
	err = run(logToStderr)
	assert.NoError(t, err)
	streams := cli.NewIOStreams()
	cmd := NewCommandWithArgs(os.Args, streams)

	//output, err := executeCommand(cmd, "run")
	//cmd.SetOut(streams.Out)
	//contents, err := ioutil.ReadAll(out)
	//assert.NoError(t, err)
	//assert.True(t, strings.Contains(string(contents), "Hello I am running"))
	output, _ := executeCommand(cmd, "diagnostics")
	assert.Equal(t, "test", output)
}

func executeCommand(root *cobra.Command, args ...string) (output string, err error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	err = root.Execute()
	if err != nil {
		fmt.Println(err)
	}

	return buf.String(), err
}
