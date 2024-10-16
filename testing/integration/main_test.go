package integration

import (
	"flag"
	"os"
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/spf13/pflag"
)

var flagSet = pflag.CommandLine

func init() {
	define.RegisterFlags("integration.", flagSet)
}

func TestMain(m *testing.M) {
	flag.Parse()

	runExitCode := m.Run()

	if define.DryRun {
		// TODO add parsing of requirements and dump them
	}

	os.Exit(runExitCode)
}
