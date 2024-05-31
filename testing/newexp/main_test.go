//go:build integration

package newexp

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Flags consts
const (
	flagPrefix           = "integration."
	skipDestroyFlag      = "skip-destroy"
	terraformDirFlag     = "terraform-dir"
	skipProvisioningFlag = "skip-provisioning"
)

// Flags globals
type testOptions struct {
	skipDestroy      bool
	skipProvisioning bool
	terraformWorkDir string
}

var flagSet = flag.CommandLine
var testOpts testOptions

// Simple package variable to test
var pkgVar string

func init() {
	err := bindTestFlags(flagPrefix, flagSet, &testOpts)
	if err != nil {
		panic(fmt.Errorf("initializing command line flags: %w", err))
	}
}

func bindTestFlags(prefix string, flagSet *flag.FlagSet, opts *testOptions) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("detecting CWD: %w", err)
	}

	// flags
	flagSet.BoolVar(&opts.skipDestroy, prefix+skipDestroyFlag, false, "Set this flag to skip destroying resources")
	flagSet.BoolVar(&opts.skipProvisioning, prefix+skipProvisioningFlag, false, "Set this flag to run directly the tests by skipping the provisioning")
	flagSet.StringVar(&opts.terraformWorkDir, prefix+terraformDirFlag, filepath.Join(cwd, "terraform"), "Directory containing terraform files")

	return nil
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	flag.Parse()

	os.Exit(innerRun(ctx, m))
}

func innerRun(ctx context.Context, m *testing.M) (returnCode int) {

	log.Printf("go test args: %s\n", os.Args)

	if !testOpts.skipProvisioning {
		// "Remote execution case"
		defer func() {
			err := tearDown(ctx)
			if err != nil {
				log.Printf("error during teardown: %s", err)
			}
		}()

		client, _, essDeployment, err := setup(ctx)
		if err != nil {
			log.Printf("error during setup: %s", err)
			return 1
		}

		cmdLine := buildRemoteTestCommand(essDeployment)

		log.Printf("full command to run on remote host: %q", cmdLine)

		session, err := client.NewSession()
		if err != nil {
			log.Printf("initiating ssh session: %s", err)
			return 1
		}
		defer session.Close()
		output, err := session.CombinedOutput(cmdLine)
		if err != nil {
			log.Printf("error running tests on remote machine: %s", err)
			returnCode = 1
		}
		log.Printf("Test run output:\n%s\n", string(output))
	} else {
		// Local execution case

		// SMALL setup for the test (this would need to be performed where the test runs)
		pkgVar = "This is not a drill."
		os.Setenv("TEST_ENV_VAR", "This is not a drill.")

		return m.Run()
	}

	return returnCode
}

func buildRemoteTestCommand(deployment *ESSDeployment) string {
	sb := new(strings.Builder)

	sb.WriteString("cd /src/elastic-agent && ")

	// FIXME Hack to have define directives work at runtime
	sb.WriteString("TEST_DEFINE_PREFIX=aaaaaa ")
	sb.WriteString(" ELASTICSEARCH_HOST=")
	sb.WriteString(deployment.ElasticsearchHost)
	sb.WriteString(" KIBANA_HOST=")
	sb.WriteString(deployment.KibanaHost)
	sb.WriteString(" ELASTICSEARCH_USERNAME=")
	sb.WriteString(deployment.ESUser)
	sb.WriteString(" ELASTICSEARCH_PASSWORD=")
	sb.WriteString(deployment.ESPassword)
	sb.WriteString(" KIBANA_USERNAME=")
	sb.WriteString(deployment.ESUser)
	sb.WriteString(" KIBANA_PASSWORD=")
	sb.WriteString(deployment.ESPassword)

	// Start with the test command
	sb.WriteString(" go test ")

	// HACK to run the correct package
	sb.WriteString(" github.com/elastic/elastic-agent/testing/newexp ")
	sb.WriteString("-tags integration")
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-"+flagPrefix) {
			// that's a flag for this test main, skip it
			continue
		}
		sb.WriteString(" ")
		sb.WriteString(arg)
	}

	// Add the "no-provision" switch for the remote run
	sb.WriteString(" -args ")
	sb.WriteString("-" + flagPrefix + skipProvisioningFlag)

	return sb.String()
}
