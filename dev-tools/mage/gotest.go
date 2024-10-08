// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/elastic/elastic-agent/dev-tools/mage/gotool"
)

// GoTestArgs are the arguments used for the "go*Test" targets and they define
// how "go test" is invoked. "go test" is always invoked with -v for verbose.
type GoTestArgs struct {
	LogName             string            // Test name used in logging.
	RunExpr             string            // Expression to pass to the -run argument of go test.
	Race                bool              // Enable race detector.
	Tags                []string          // Build tags to enable.
	ExtraFlags          []string          // Extra flags to pass to 'go test'.
	Packages            []string          // Packages to test.
	Env                 map[string]string // Env vars to add to the current env.
	OutputFile          string            // File to write verbose test output to.
	JUnitReportFile     string            // File to write a JUnit XML test report to.
	CoverageProfileFile string            // Test coverage profile file (enables -cover).
	Output              io.Writer         // Write stderr and stdout to Output if set
}

// TestBinaryArgs are the arguments used when building binary for testing.
type TestBinaryArgs struct {
	Name       string // Name of the binary to build
	InputFiles []string
}

func makeGoTestArgs(name string) GoTestArgs {
	fileName := fmt.Sprintf("build/TEST-go-%s", strings.Replace(strings.ToLower(name), " ", "_", -1))
	params := GoTestArgs{
		LogName:         name,
		Race:            RaceDetector,
		Packages:        []string{"./..."},
		OutputFile:      fileName + ".out",
		JUnitReportFile: fileName + ".xml",
		Tags:            testTagsFromEnv(),
	}
	if TestCoverage {
		params.CoverageProfileFile = fileName + ".cov"
	}
	return params
}

func makeGoTestArgsForModule(name, module string) GoTestArgs {
	fileName := fmt.Sprintf("build/TEST-go-%s-%s", strings.Replace(strings.ToLower(name), " ", "_", -1),
		strings.Replace(strings.ToLower(module), " ", "_", -1))
	params := GoTestArgs{
		LogName:         fmt.Sprintf("%s-%s", name, module),
		Race:            RaceDetector,
		Packages:        []string{fmt.Sprintf("./module/%s/...", module)},
		OutputFile:      fileName + ".out",
		JUnitReportFile: fileName + ".xml",
		Tags:            testTagsFromEnv(),
	}
	if TestCoverage {
		params.CoverageProfileFile = fileName + ".cov"
	}
	return params
}

// testTagsFromEnv gets a list of comma-separated tags from the TEST_TAGS
// environment variables, e.g: TEST_TAGS=aws,azure.
func testTagsFromEnv() []string {
	return strings.Split(strings.Trim(os.Getenv("TEST_TAGS"), ", "), ",")
}

// DefaultGoTestUnitArgs returns a default set of arguments for running
// all unit tests. We tag unit test files with '!integration'.
func DefaultGoTestUnitArgs() GoTestArgs { return makeGoTestArgs("Unit") }

// DefaultGoTestIntegrationArgs returns a default set of arguments for running
// all integration tests. We tag integration test files with 'integration'.
func DefaultGoTestIntegrationArgs() GoTestArgs {
	args := makeGoTestArgs("Integration")
	args.Tags = append(args.Tags, "integration")
	return args
}

// GoTestIntegrationArgsForModule returns a default set of arguments for running
// module integration tests. We tag integration test files with 'integration'.
func GoTestIntegrationArgsForModule(module string) GoTestArgs {
	args := makeGoTestArgsForModule("Integration", module)
	args.Tags = append(args.Tags, "integration")
	return args
}

// DefaultTestBinaryArgs returns the default arguments for building
// a binary for testing.
func DefaultTestBinaryArgs() TestBinaryArgs {
	return TestBinaryArgs{
		Name: BeatName,
	}
}

// GoTestIntegrationForModule executes the Go integration tests sequentially.
// Currently all test cases must be present under "./module" directory.
//
// Motivation: previous implementation executed all integration tests at once,
// causing high CPU load, high memory usage and resulted in timeouts.
//
// This method executes integration tests for a single module at a time.
// Use TEST_COVERAGE=true to enable code coverage profiling.
// Use RACE_DETECTOR=true to enable the race detector.
// Use MODULE=module to run only tests for `module`.
func GoTestIntegrationForModule(ctx context.Context) error {
	module := EnvOr("MODULE", "")
	modulesDirEntry, err := os.ReadDir("./module")
	if err != nil {
		return err
	}

	foundModule := false
	failedModules := []string{}
	for _, fi := range modulesDirEntry {
		if !fi.IsDir() {
			continue
		}
		if module != "" && module != fi.Name() {
			continue
		}
		foundModule = true

		// Set MODULE because only want that modules tests to run inside the testing environment.
		env := map[string]string{"MODULE": fi.Name()}
		passThroughEnvs(env, IntegrationTestEnvVars()...)
		runners, err := NewIntegrationRunners(path.Join("./module", fi.Name()), env)
		if err != nil {
			return fmt.Errorf("test setup failed for module %s: %w", fi.Name(), err)
		}
		err = runners.Test("goIntegTest", func() error {
			err := GoTest(ctx, GoTestIntegrationArgsForModule(fi.Name()))
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			// err will already be report to stdout, collect failed module to report at end
			failedModules = append(failedModules, fi.Name())
		}
	}
	if module != "" && !foundModule {
		return fmt.Errorf("no module %s", module)
	}
	if len(failedModules) > 0 {
		return fmt.Errorf("failed modules: %s", strings.Join(failedModules, ", "))
	}
	return nil
}

// InstallGoTestTools installs additional tools that are required to run unit and integration tests.
func InstallGoTestTools() error {
	return gotool.Install(
		gotool.Install.Package("gotest.tools/gotestsum"),
	)
}

func GoTestBuild(ctx context.Context, params GoTestArgs) error {
	if params.OutputFile == "" {
		return fmt.Errorf("missing output file")
	}

	fmt.Println(">> go test:", params.LogName, "Building Test Binary")

	args := []string{"test", "-c", "-o", params.OutputFile}

	if len(params.Tags) > 0 {
		params := strings.Join(params.Tags, " ")
		if params != "" {
			args = append(args, "-tags", params)
		}
	}

	args = append(args, params.Packages...)

	goTestBuild := makeCommand(ctx, params.Env, "go", args...)

	err := goTestBuild.Run()
	if err != nil {
		return err
	}
	return nil
}

// GoTest invokes "go test" and reports the results to stdout. It returns an
// error if there was any failure executing the tests or if there were any
// test failures.
func GoTest(ctx context.Context, params GoTestArgs) error {
	mg.Deps(InstallGoTestTools)

	fmt.Println(">> go test:", params.LogName, "Testing")

	// We use gotestsum to drive the tests and produce a junit report.
	// The tool runs `go test -json` in order to produce a structured log which makes it easier
	// to parse the actual test output.
	// Of OutputFile is given the original JSON file will be written as well.
	//
	// The runner needs to set CLI flags for gotestsum and for "go test". We track the different
	// CLI flags in the gotestsumArgs and testArgs variables, such that we can finally produce command like:
	//   $ gotestsum <gotestsum args> -- <go test args>
	//
	// The additional arguments given via GoTestArgs are applied to `go test` only. Callers can not
	// modify any of the gotestsum arguments.

	gotestsumArgs := []string{"--no-color"}
	if mg.Verbose() {
		gotestsumArgs = append(gotestsumArgs, "-f", "standard-verbose")
	} else {
		gotestsumArgs = append(gotestsumArgs, "-f", "standard-quiet")
	}
	if params.JUnitReportFile != "" {
		CreateDir(params.JUnitReportFile)
		gotestsumArgs = append(gotestsumArgs, "--junitfile", params.JUnitReportFile)
	}
	if params.OutputFile != "" {
		CreateDir(params.OutputFile)
		gotestsumArgs = append(gotestsumArgs, "--jsonfile", params.OutputFile+".json")
	}

	var testArgs []string

	if params.Race {
		testArgs = append(testArgs, "-race")
	}

	if len(params.Tags) > 0 {
		params := strings.Join(params.Tags, " ")
		if params != "" {
			testArgs = append(testArgs, "-tags", params)
		}
	}
	if params.CoverageProfileFile != "" {
		params.CoverageProfileFile = createDir(filepath.Clean(params.CoverageProfileFile))
		testArgs = append(testArgs,
			"-covermode=atomic",
			"-coverprofile="+params.CoverageProfileFile,
		)
	}

	// Pass the go test extra flags BEFORE the RunExpr.
	// TL;DR: This is needed to make sure that a -test.run flag specified in the GOTEST_FLAGS environment variable does
	// not interfere with the batching done by the framework.
	//
	// Full explanation:
	// The integration test framework runs the tests twice:
	// - the first time we pass a special tag that make all the define statements in the tests skip the test and dump the requirements.
	//   This output is processed by the integration test framework to discover the tests and the set of environments/machines
	//   we will need to spawn and allocate the tests to the various machines. (see batch.go for details)
	// - the second time we run the tests (here) the integration test framework adds a -test.run flag when launching go test
	//   on the remote machine to make sure that only the tests corresponding to that batch are executed.
	//
	// By specifying the extra flags before the -test.run for the batch we make sure that the last flag definition "wins"
	// (have a look at the unit test in batch_test.go), so that whatever run constraint is specified in GOTEST_FLAGS
	// participates in the discovery and batching (1st go test execution) but doesn't override the actual execution on
	// the remote machine (2nd go test execution).
	testArgs = append(testArgs, params.ExtraFlags...)
	if params.RunExpr != "" {
		testArgs = append(testArgs, "-run", params.RunExpr)
	}
	testArgs = append(testArgs, params.Packages...)

	args := append(gotestsumArgs, append([]string{"--"}, testArgs...)...)
	fmt.Println(">> ARGS:", params.LogName, "Command:", "gotestsum", strings.Join(args, " "))

	goTest := makeCommand(ctx, params.Env, "gotestsum", args...)
	// Wire up the outputs.
	var outputs []io.Writer
	if params.Output != nil {
		outputs = append(outputs, params.Output)
	}

	if params.OutputFile != "" {
		fileOutput, err := os.Create(createDir(params.OutputFile))
		if err != nil {
			return fmt.Errorf("failed to create go test output file: %w", err)
		}
		defer fileOutput.Close()
		outputs = append(outputs, fileOutput)
	}
	output := io.MultiWriter(outputs...)
	if params.Output == nil {
		goTest.Stdout = io.MultiWriter(output, os.Stdout)
		goTest.Stderr = io.MultiWriter(output, os.Stderr)
	} else {
		goTest.Stdout = output
		goTest.Stderr = output
	}

	err := goTest.Run()

	var goTestErr *exec.ExitError
	if err != nil {
		// Command ran.
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return fmt.Errorf("failed to execute go: %w", err)
		}

		// Command ran but failed. Process the output.
		goTestErr = exitErr
	}

	if goTestErr != nil {
		// No packages were tested. Probably the code didn't compile.
		return fmt.Errorf("go test returned a non-zero value: %w", goTestErr)
	}

	// Generate a HTML code coverage report.
	var htmlCoverReport string
	if params.CoverageProfileFile != "" {
		htmlCoverReport = strings.TrimSuffix(params.CoverageProfileFile,
			filepath.Ext(params.CoverageProfileFile)) + ".html"
		coverToHTML := sh.RunCmd("go", "tool", "cover",
			"-html="+params.CoverageProfileFile,
			"-o", htmlCoverReport)
		if err = coverToHTML(); err != nil {
			return fmt.Errorf("failed to write HTML code coverage report: %w", err)
		}
	}

	// Generate an XML code coverage report.
	var codecovReport string
	if params.CoverageProfileFile != "" {
		fmt.Println(">> go run gocover-cobertura:", params.CoverageProfileFile, "Started")

		// execute gocover-cobertura in order to create cobertura report
		// install pre-requisites
		installCobertura := sh.RunCmd("go", "install", "github.com/boumenot/gocover-cobertura@latest")
		if err = installCobertura(); err != nil {
			return fmt.Errorf("failed to install gocover-cobertura: %w", err)
		}

		codecovReport = strings.TrimSuffix(params.CoverageProfileFile,
			filepath.Ext(params.CoverageProfileFile)) + "-cov.xml"

		coverage, err := os.ReadFile(params.CoverageProfileFile)
		if err != nil {
			return fmt.Errorf("failed to read code coverage report: %w", err)
		}

		coberturaFile, err := os.Create(codecovReport)
		if err != nil {
			return err
		}
		defer coberturaFile.Close()

		coverToXML := exec.Command("gocover-cobertura")
		coverToXML.Stdout = coberturaFile
		coverToXML.Stderr = os.Stderr
		coverToXML.Stdin = bytes.NewReader(coverage)
		if err = coverToXML.Run(); err != nil {
			return fmt.Errorf("failed to write XML code coverage report: %w", err)
		}
		fmt.Println(">> go run gocover-cobertura:", params.CoverageProfileFile, "Created")
	}

	// Return an error indicating that testing failed.
	if goTestErr != nil {
		fmt.Println(">> go test:", params.LogName, "Test Failed")
		return fmt.Errorf("go test returned a non-zero value: %w", goTestErr)
	}

	fmt.Println(">> go test:", params.LogName, "Test Passed")
	return nil
}

func makeCommand(ctx context.Context, env map[string]string, cmd string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, cmd, args...)
	c.Env = os.Environ()
	for k, v := range env {
		c.Env = append(c.Env, k+"="+v)
	}
	c.Stdout = io.Discard
	if mg.Verbose() {
		c.Stdout = os.Stdout
	}
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	log.Println("exec:", cmd, strings.Join(args, " "))
	fmt.Println("exec:", cmd, strings.Join(args, " "))
	return c
}

// BuildSystemTestBinary runs BuildSystemTestGoBinary with default values.
func BuildSystemTestBinary() error {
	return BuildSystemTestGoBinary(DefaultTestBinaryArgs())
}

// BuildSystemTestGoBinary build a binary for testing that is instrumented for
// testing and measuring code coverage. The binary is only instrumented for
// coverage when TEST_COVERAGE=true (default is false).
func BuildSystemTestGoBinary(binArgs TestBinaryArgs) error {
	args := []string{
		"test", "-c",
		"-o", binArgs.Name + ".test",
	}
	if TestCoverage {
		args = append(args, "-coverpkg", "./...")
	}
	if len(binArgs.InputFiles) > 0 {
		args = append(args, binArgs.InputFiles...)
	}

	start := time.Now()
	defer func() {
		log.Printf("BuildSystemTestGoBinary (go %v) took %v.", strings.Join(args, " "), time.Since(start))
	}()
	return sh.RunV("go", args...)
}
