package integration

import (
	"flag"
	"os"
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

var flagSet = flag.CommandLine

func init() {
	define.RegisterFlags("integration.", flagSet)
}

func TestMain(m *testing.M) {
	flag.Parse()
	define.ParseFlags()
	runExitCode := m.Run()

	if define.DryRun {
		// TODO add parsing of requirements and dump them
	}

	os.Exit(runExitCode)
}
