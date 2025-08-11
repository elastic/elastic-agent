package main

import (
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/internal/edot/cmd"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

func main() {
	var err error
	defer func() {
		if err != nil {
			os.Exit(1) // defer os exit and allow other goroutines to cleanup
		}
	}()

	pj, err := process.CreateJobObject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize process job object: %v\n", err)
		return
	}
	defer pj.Close()

	runCmd := cmd.NewCommandWithArgs(os.Args, cli.NewIOStreams())
	err = runCmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
}
