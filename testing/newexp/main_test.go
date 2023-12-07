package newexp

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
)

const flagPrefix = "integration."

type testOptions struct {
	skipDestroy      bool
	terraformWorkDir string
}

var testOpts testOptions
var pkgVar string

func init() {
	bindTestFlags(flagPrefix, flag.CommandLine, &testOpts)
}

func bindTestFlags(prefix string, flagSet *flag.FlagSet, opts *testOptions) {
	// flags
	flagSet.BoolVar(&opts.skipDestroy, prefix+"skip-destroy", false, "Set this flag to skip destroying resources")
	cwd, err := os.Getwd()
	if err != nil {
		panic(fmt.Errorf("detecting CWD: %w", err))
	}
	flagSet.StringVar(&opts.terraformWorkDir, prefix+"terraform-dir", filepath.Join(cwd, "testdata", "terraform"), "Directory containing terraform files")
}

// Terraform globals
var terraformInstall *releases.ExactVersion
var terraform *tfexec.Terraform

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	flag.Parse()

	os.Exit(innerRun(ctx, m))
}

func innerRun(ctx context.Context, m *testing.M) int {
	if err := setup(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error running tests: %s", err)
		os.Exit(1)
	}
	defer tearDown(ctx)
	fmt.Fprintf(os.Stderr, "go test args: %s\n", os.Args)

	return m.Run()
}

func setup(ctx context.Context) error {
	// Setup terraform instances
	err := prepareTerraform(ctx)
	if err != nil {
		return fmt.Errorf("setup error: %w", err)
	}

	err = provisionMachines(ctx)

	pkgVar = "This is not a drill."
	return os.Setenv("TEST_ENV_VAR", "This is not a drill.")
}

func provisionMachines(ctx context.Context) error {
	err := terraform.Init(ctx, tfexec.Upgrade(true))
	if err != nil {
		return fmt.Errorf("error running Init: %w", err)
	}

	planFilePath := filepath.Join(testOpts.terraformWorkDir, "main.tf.plan")
	tfvarsFilePath := filepath.Join(testOpts.terraformWorkDir, "main.tfvars")
	changesRequired, err := terraform.Plan(ctx, tfexec.VarFile(tfvarsFilePath), tfexec.Out(planFilePath))
	if err != nil {
		return fmt.Errorf("error running Plan: %w", err)
	}

	if !changesRequired {
		// there are no changes required
		return nil
	}

	plan, err := terraform.ShowPlanFile(ctx, planFilePath)
	if err != nil {
		return fmt.Errorf("error running Show: %w", err)
	}
	fmt.Fprintf(os.Stderr, "terraform plan:\n%+v\n", plan)
	err = terraform.Apply(ctx, tfexec.VarFile(tfvarsFilePath))
	if err != nil {
		return fmt.Errorf("error running Apply: %w", err)
	}

	state, err := terraform.Show(ctx)
	if err != nil {
		return fmt.Errorf("error running Show: %w", err)
	}

	fmt.Println(state.FormatVersion) // "0.1"
	return nil
}

func tearDown(ctx context.Context) error {
	if testOpts.skipDestroy {
		return nil
	}

	if terraform == nil {
		// terraform does not seem to be installed properly
		return fmt.Errorf("terraform does not seem to install correctly")
	}

	teardownError := terraform.Destroy(ctx, tfexec.VarFile(filepath.Join(testOpts.terraformWorkDir, "main.tfvars")))
	return errors.Join(teardownError, terraformInstall.Remove(ctx))
}

func prepareTerraform(ctx context.Context) error {
	installer := &releases.ExactVersion{
		Product: product.Terraform,
		Version: version.Must(version.NewVersion("1.8.4")),
	}
	execPath, err := installer.Install(ctx)
	if err != nil {
		return fmt.Errorf("error installing Terraform: %w", err)
	}
	terraformInstall = installer

	fmt.Fprintf(os.Stderr, "Installed terraform, exec path: %s\n", execPath)

	fmt.Fprintf(os.Stderr, "working dir: %s\n", testOpts.terraformWorkDir)

	tf, err := tfexec.NewTerraform(testOpts.terraformWorkDir, execPath)
	if err != nil {
		log.Fatalf("error running NewTerraform: %s", err)
	}
	terraform = tf

	return nil
}
