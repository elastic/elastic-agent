// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build mage

package main

import (
	"bufio"
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"maps"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/otiai10/copy"

	"github.com/elastic/elastic-agent/dev-tools/mage"
	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
	"github.com/elastic/elastic-agent/dev-tools/mage/downloads"
	"github.com/elastic/elastic-agent/dev-tools/mage/manifest"
	"github.com/elastic/elastic-agent/dev-tools/mage/pkgcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/pkg/testing/buildkite"
	tcommon "github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/ess"
	"github.com/elastic/elastic-agent/pkg/testing/kubernetes/kind"
	"github.com/elastic/elastic-agent/pkg/testing/multipass"
	"github.com/elastic/elastic-agent/pkg/testing/ogc"
	"github.com/elastic/elastic-agent/pkg/testing/runner"
	"github.com/elastic/elastic-agent/pkg/testing/tools/git"
	pv "github.com/elastic/elastic-agent/pkg/testing/tools/product_versions"
	"github.com/elastic/elastic-agent/pkg/testing/tools/snapshots"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
	bversion "github.com/elastic/elastic-agent/version"

	// mage:import
	"github.com/elastic/elastic-agent/dev-tools/mage/target/common"
	// mage:import
	_ "github.com/elastic/elastic-agent/dev-tools/mage/target/integtest/notests"
	// mage:import
	"github.com/elastic/elastic-agent/dev-tools/mage/target/test"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
)

const (
	goLicenserRepo    = "github.com/elastic/go-licenser"
	buildDir          = "build"
	metaDir           = "_meta"
	snapshotEnv       = "SNAPSHOT"
	devEnv            = "DEV"
	externalArtifacts = "EXTERNAL"
	platformsEnv      = "PLATFORMS"
	packagesEnv       = "PACKAGES"
	configFile        = "elastic-agent.yml"
	agentDropPath     = "AGENT_DROP_PATH"
	checksumFilename  = "checksum.yml"
	commitLen         = 7

	cloudImageTmpl = "docker.elastic.co/observability-ci/elastic-agent:%s"

	baseURLForStagingDRA = "https://staging.elastic.co/"
	agentCoreProjectName = "elastic-agent-core"

	helmChartPath = "./deploy/helm/elastic-agent"

	sha512FileExt = ".sha512"
)

var (
	// Aliases for commands required by master makefile
	Aliases = map[string]interface{}{
		"build": Build.All,
		"demo":  Demo.Enroll,
	}

	errNoManifest         = errors.New(fmt.Sprintf("missing %q environment variable", mage.ManifestUrlEnvVar))
	errNoAgentDropPath    = errors.New("missing AGENT_DROP_PATH environment variable")
	errAtLeastOnePlatform = errors.New("elastic-agent package is expected to build at least one platform package")

	// goIntegTestTimeout is the timeout passed to each instance of 'go test' used in integration tests.
	goIntegTestTimeout = 2 * time.Hour
	// goProvisionAndTestTimeout is the timeout used for both provisioning and running tests.
	goProvisionAndTestTimeout = goIntegTestTimeout + 30*time.Minute
)

func init() {
	common.RegisterCheckDeps(Update, Check.All)
	test.RegisterDeps(UnitTest)
	devtools.BeatLicense = "Elastic License 2.0"
	devtools.BeatDescription = "Elastic Agent - single, unified way to add monitoring for logs, metrics, and other types of data to a host."

	devtools.Platforms = devtools.Platforms.Filter("!linux/386")
	devtools.Platforms = devtools.Platforms.Filter("!windows/386")
}

// Default set to build everything by default.
var Default = Build.All

// Build namespace used to build binaries.
type Build mg.Namespace

// Test namespace contains all the task for testing the projects.
type Test mg.Namespace

// Check namespace contains tasks related check the actual code quality.
type Check mg.Namespace

// Prepare tasks related to bootstrap the environment or get information about the environment.
type Prepare mg.Namespace

// Format automatically format the code.
type Format mg.Namespace

// Demo runs agent out of container.
type Demo mg.Namespace

// Dev runs package and build for dev purposes.
type Dev mg.Namespace

// Cloud produces or pushes cloud image for cloud testing.
type Cloud mg.Namespace

// Integration namespace contains tasks related to operating and running integration tests.
type Integration mg.Namespace

// Otel namespace contains Open Telemetry related tasks.
type Otel mg.Namespace

func CheckNoChanges() error {
	fmt.Println(">> fmt - go run")
	err := sh.RunV("go", "mod", "tidy", "-v")
	if err != nil {
		return fmt.Errorf("failed running go mod tidy, please fix the issues reported: %w", err)
	}
	fmt.Println(">> fmt - git diff")
	err = sh.RunV("git", "diff")
	if err != nil {
		return fmt.Errorf("failed running git diff, please fix the issues reported: %w", err)
	}
	fmt.Println(">> fmt - git update-index")
	err = sh.RunV("git", "update-index", "--refresh")
	if err != nil {
		return fmt.Errorf("failed running git update-index --refresh, please fix the issues reported: %w", err)
	}
	fmt.Println(">> fmt - git diff-index")
	err = sh.RunV("git", "diff-index", "--exit-code", "HEAD", " --")
	if err != nil {
		return fmt.Errorf("failed running go mod tidy, please fix the issues reported: %w", err)
	}
	return nil
}

// Env returns information about the environment.
func (Prepare) Env() {
	mg.Deps(Mkdir("build"), Build.GenerateConfig)
	RunGo("version")
	RunGo("env")
}

// Build builds the agent binary with DEV flag set.
func (Dev) Build() {
	dev := os.Getenv(devEnv)
	defer os.Setenv(devEnv, dev)

	os.Setenv(devEnv, "true")
	devtools.DevBuild = true
	mg.Deps(Build.All)
}

// Package bundles the agent binary with DEV flag set.
func (Dev) Package(ctx context.Context) {
	dev := os.Getenv(devEnv)
	defer os.Setenv(devEnv, dev)

	os.Setenv(devEnv, "true")

	if _, hasExternal := os.LookupEnv(externalArtifacts); !hasExternal {
		devtools.ExternalBuild = true
	}

	devtools.DevBuild = true
	Package(ctx)
}

func mocksPath() (string, error) {
	repositoryRoot, err := findRepositoryRoot()
	if err != nil {
		return "", fmt.Errorf("finding repository root: %w", err)
	}
	return filepath.Join(repositoryRoot, "testing", "mocks"), nil
}

func (Dev) CleanMocks() error {
	mPath, err := mocksPath()
	if err != nil {
		return fmt.Errorf("retrieving mocks path: %w", err)
	}
	err = os.RemoveAll(mPath)
	if err != nil {
		return fmt.Errorf("removing mocks: %w", err)
	}
	return nil
}

func (Dev) RegenerateMocks() error {
	mg.Deps(Dev.CleanMocks)
	err := sh.Run("mockery")
	if err != nil {
		return fmt.Errorf("generating mocks: %w", err)
	}

	// change CWD
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("retrieving CWD: %w", err)
	}
	// restore the working directory when exiting the function
	defer func() {
		err := os.Chdir(workingDir)
		if err != nil {
			panic(fmt.Errorf("failed to restore working dir %q: %w", workingDir, err))
		}
	}()

	mPath, err := mocksPath()
	if err != nil {
		return fmt.Errorf("retrieving mocks path: %w", err)
	}

	err = os.Chdir(mPath)
	if err != nil {
		return fmt.Errorf("changing current directory to %q: %w", mPath, err)
	}

	mg.Deps(devtools.AddLicenseHeaders)
	mg.Deps(devtools.GoImports)
	return nil
}

// InstallGoLicenser install go-licenser to check license of the files.
func (Prepare) InstallGoLicenser() error {
	return GoInstall(goLicenserRepo)
}

// All build all the things for the current projects.
func (Build) All() {
	mg.Deps(Build.Binary)
}

// GenerateConfig generates the configuration from _meta/elastic-agent.yml
func (Build) GenerateConfig() error {
	mg.Deps(Mkdir(buildDir))
	return sh.Copy(filepath.Join(buildDir, configFile), filepath.Join(metaDir, configFile))
}

// GolangCrossBuildOSS build the Beat binary inside of the golang-builder.
// Do not use directly, use crossBuild instead.
func GolangCrossBuildOSS() error {
	params := devtools.DefaultGolangCrossBuildArgs()
	injectBuildVars(params.Vars)
	return devtools.GolangCrossBuild(params)
}

// GolangCrossBuild build the Beat binary inside of the golang-builder.
// Do not use directly, use crossBuild instead.
func GolangCrossBuild() error {
	params := devtools.DefaultGolangCrossBuildArgs()
	params.OutputDir = "build/golang-crossbuild"
	injectBuildVars(params.Vars)

	if err := devtools.GolangCrossBuild(params); err != nil {
		return err
	}

	// TODO: no OSS bits just yet
	// return GolangCrossBuildOSS()

	return nil
}

// BuildGoDaemon builds the go-daemon binary (use crossBuildGoDaemon).
func BuildGoDaemon() error {
	return devtools.BuildGoDaemon()
}

// BinaryOSS build the fleet artifact.
func (Build) BinaryOSS() error {
	mg.Deps(Prepare.Env)
	buildArgs := devtools.DefaultBuildArgs()
	buildArgs.Name = "elastic-agent-oss"
	buildArgs.OutputDir = buildDir
	injectBuildVars(buildArgs.Vars)

	return devtools.Build(buildArgs)
}

// Binary build the fleet artifact.
func (Build) Binary() error {
	mg.Deps(Prepare.Env)

	buildArgs := devtools.DefaultBuildArgs()
	buildArgs.OutputDir = buildDir
	injectBuildVars(buildArgs.Vars)

	return devtools.Build(buildArgs)
}

// Clean up dev environment.
func (Build) Clean() error {
	absBuildDir, err := filepath.Abs(buildDir)
	if err != nil {
		return fmt.Errorf("cannot get absolute path of build dir: %w", err)
	}
	if err := os.RemoveAll(absBuildDir); err != nil {
		return fmt.Errorf("cannot remove build dir '%s': %w", absBuildDir, err)
	}

	testBinariesPath, err := getTestBinariesPath()
	if err != nil {
		return fmt.Errorf("cannot remove test binaries: %w", err)
	}

	if mg.Verbose() {
		fmt.Println("removed", absBuildDir)
		for _, b := range testBinariesPath {
			fmt.Println("removed", b)
		}
	}

	return nil
}

func getTestBinariesPath() ([]string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("could not get working directory: %w", err)
	}

	testBinaryPkgs := []string{
		filepath.Join(wd, "pkg", "component", "fake", "component"),
		filepath.Join(wd, "internal", "pkg", "agent", "install", "testblocking"),
	}
	return testBinaryPkgs, nil
}

// TestBinaries build the required binaries for the test suite.
func (Build) TestBinaries() error {
	testBinaryPkgs, err := getTestBinariesPath()
	if err != nil {
		fmt.Errorf("cannot build test binaries: %w", err)
	}

	for _, pkg := range testBinaryPkgs {
		binary := filepath.Base(pkg)
		if runtime.GOOS == "windows" {
			binary += ".exe"
		}

		outputName := filepath.Join(pkg, binary)
		err := RunGo("build", "-o", outputName, filepath.Join(pkg))
		if err != nil {
			return err
		}
		err = os.Chmod(outputName, 0755)
		if err != nil {
			return err
		}
	}
	return nil
}

// All run all the code checks.
func (Check) All() {
	mg.SerialDeps(Check.License, Integration.Check)
}

// License makes sure that all the Golang files have the appropriate license header.
func (Check) License() error {
	mg.Deps(Prepare.InstallGoLicenser)
	// exclude copied files until we come up with a better option
	return sh.RunV("go-licenser", "-d", "-license", "Elasticv2")
}

// Changes run git status --porcelain and return an error if we have changes or uncommitted files.
func (Check) Changes() error {
	out, err := sh.Output("git", "status", "--porcelain")
	if err != nil {
		return errors.New("cannot retrieve hash")
	}

	if len(out) != 0 {
		fmt.Fprintln(os.Stderr, "Changes:")
		fmt.Fprintln(os.Stderr, out)
		return fmt.Errorf("uncommited changes")
	}
	return nil
}

// All runs all the tests.
func (Test) All() {
	mg.SerialDeps(Test.Unit)
}

// Unit runs all the unit tests.
func (Test) Unit(ctx context.Context) error {
	mg.Deps(Prepare.Env, Build.TestBinaries)
	params := devtools.DefaultGoTestUnitArgs()
	return devtools.GoTest(ctx, params)
}

// Coverage takes the coverages report from running all the tests and display the results in the browser.
func (Test) Coverage() error {
	mg.Deps(Prepare.Env, Build.TestBinaries)
	return RunGo("tool", "cover", "-html="+filepath.Join(buildDir, "coverage.out"))
}

// All format automatically all the codes.
func (Format) All() {
	mg.SerialDeps(Format.License)
}

// License applies the right license header.
func (Format) License() error {
	mg.Deps(Prepare.InstallGoLicenser)
	return sh.RunV("go-licenser", "-license", "Elastic")
}

// AssembleDarwinUniversal merges the darwin/amd64 and darwin/arm64 into a single
// universal binary using `lipo`. It's automatically invoked by CrossBuild whenever
// the darwin/amd64 and darwin/arm64 are present.
func AssembleDarwinUniversal() error {
	cmd := "lipo"

	if _, err := exec.LookPath(cmd); err != nil {
		return fmt.Errorf("%q is required to assemble the universal binary: %w",
			cmd, err)
	}

	var lipoArgs []string
	args := []string{
		"build/golang-crossbuild/%s-darwin-universal",
		"build/golang-crossbuild/%s-darwin-arm64",
		"build/golang-crossbuild/%s-darwin-amd64",
	}

	for _, arg := range args {
		lipoArgs = append(lipoArgs, fmt.Sprintf(arg, devtools.BeatName))
	}

	lipo := sh.RunCmd(cmd, "-create", "-output")
	return lipo(lipoArgs...)
}

// Package packages the Beat for distribution.
// Use SNAPSHOT=true to build snapshots.
// Use PLATFORMS to control the target platforms.
// Use VERSION_QUALIFIER to control the version qualifier.
func Package(ctx context.Context) error {
	start := time.Now()
	defer func() { fmt.Println("package ran for", time.Since(start)) }()

	platforms := devtools.Platforms.Names()
	if len(platforms) == 0 {
		panic("elastic-agent package is expected to build at least one platform package")
	}

	var err error
	var manifestResponse *manifest.Build
	if devtools.PackagingFromManifest {
		manifestResponse, _, err = downloadManifestAndSetVersion(ctx, devtools.ManifestURL)
		if err != nil {
			return fmt.Errorf("failed downloading manifest: %w", err)
		}
	}

	var dependenciesVersion string
	if beatVersion, found := os.LookupEnv("BEAT_VERSION"); !found {
		dependenciesVersion = bversion.GetDefaultVersion()
	} else {
		dependenciesVersion = beatVersion
	}

	packageAgent(ctx, platforms, dependenciesVersion, manifestResponse, mg.F(devtools.UseElasticAgentPackaging), mg.F(CrossBuild), devtools.SelectedPackageTypes)
	return nil
}

// DownloadManifest downloads the provided manifest file into the predefined folder and downloads all components in the manifest.
func DownloadManifest(ctx context.Context) error {
	fmt.Println("--- Downloading manifest")
	start := time.Now()
	defer func() { fmt.Println("Downloading manifest took", time.Since(start)) }()

	dropPath, found := os.LookupEnv(agentDropPath)

	if !found {
		return errNoAgentDropPath
	}

	if !devtools.PackagingFromManifest {
		return errNoManifest
	}

	platforms := devtools.Platforms.Names()
	if len(platforms) == 0 {
		return errAtLeastOnePlatform
	}

	if e := manifest.DownloadComponents(ctx, devtools.ManifestURL, platforms, dropPath); e != nil {
		return fmt.Errorf("failed to download the manifest file, %w", e)
	}
	log.Printf(">> Completed downloading packages from manifest into drop-in %s", dropPath)

	return nil
}

// FixDRADockerArtifacts is a workaround for the DRA artifacts produced by the package target. We had to do
// because the initial unified release manager DSL code required specific names that the package does not produce,
// we wanted to keep backwards compatibility with the artifacts of the unified release and the DRA.
// this follows the same logic as https://github.com/elastic/beats/blob/2fdefcfbc783eb4710acef07d0ff63863fa00974/.ci/scripts/prepare-release-manager.sh
func FixDRADockerArtifacts() error {
	fmt.Println("--- Fixing Docker DRA artifacts")
	distributionsPath := filepath.Join("build", "distributions")
	// Find all the files with the given name
	matches, err := filepath.Glob(filepath.Join(distributionsPath, "*docker.tar.gz*"))
	if err != nil {
		return err
	}
	if mg.Verbose() {
		log.Printf("--- Found artifacts to rename %s %d", distributionsPath, len(matches))
	}
	// Match the artifact name and break down into groups so that we can reconstruct the names as its expected by the DRA DSL
	// As SNAPSHOT keyword or BUILDID are optional, capturing the separator - or + with the value.
	artifactRegexp, err := regexp.Compile(`([\w+-]+)-(([0-9]+)\.([0-9]+)\.([0-9]+))([-|\+][\w]+)?-([\w]+)-([\w]+)\.([\w]+)\.([\w.]+)`)
	if err != nil {
		return err
	}
	for _, m := range matches {
		artifactFile, err := os.Stat(m)
		if err != nil {
			return fmt.Errorf("failed stating file: %w", err)
		}
		if artifactFile.IsDir() {
			continue
		}
		match := artifactRegexp.FindAllStringSubmatch(artifactFile.Name(), -1)
		// The groups here is tightly coupled with the regexp above.
		// match[0][6] already contains the separator so no need to add before the variable
		targetName := fmt.Sprintf("%s-%s%s-%s-image-%s-%s.%s", match[0][1], match[0][2], match[0][6], match[0][9], match[0][7], match[0][8], match[0][10])
		if mg.Verbose() {
			fmt.Printf("%#v\n", match)
			fmt.Printf("Artifact: %s \n", artifactFile.Name())
			fmt.Printf("Renamed:  %s \n", targetName)
		}
		renameErr := os.Rename(filepath.Join(distributionsPath, artifactFile.Name()), filepath.Join(distributionsPath, targetName))
		if renameErr != nil {
			return renameErr
		}
		if mg.Verbose() {
			fmt.Println("Renamed artifact")
		}
	}
	return nil
}

func requiredPackagesPresent(basePath, beat, version string, requiredPackages []string) bool {
	for _, pkg := range requiredPackages {
		packageName := fmt.Sprintf("%s-%s-%s", beat, version, pkg)
		path := filepath.Join(basePath, "build", "distributions", packageName)

		if _, err := os.Stat(path); err != nil {
			fmt.Printf("Package %q does not exist on path: %s\n", packageName, path)
			return false
		}
	}
	return true
}

// TestPackages tests the generated packages (i.e. file modes, owners, groups).
func TestPackages() error {
	fmt.Println("--- TestPackages, the generated packages (i.e. file modes, owners, groups).")
	return devtools.TestPackages()
}

// RunGo runs go command and output the feedback to the stdout and the stderr.
func RunGo(args ...string) error {
	return sh.RunV(mg.GoCmd(), args...)
}

// GoInstall installs a tool by calling `go install <link>
func GoInstall(link string) error {
	_, err := sh.Exec(map[string]string{}, os.Stdout, os.Stderr, "go", "install", link)
	return err
}

// Mkdir returns a function that create a directory.
func Mkdir(dir string) func() error {
	return func() error {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory: %v, error: %+v", dir, err)
		}
		return nil
	}
}

func commitID() string {
	commitID, err := sh.Output("git", "rev-parse", "--short", "HEAD")
	if err != nil {
		return "cannot retrieve hash"
	}
	return commitID
}

// Update is an alias for executing control protocol, configs, and specs.
func Update() {
	mg.SerialDeps(Config, BuildPGP, BuildFleetCfg, Otel.Readme)
}

func EnsureCrossBuildOutputDir() error {
	repositoryRoot, err := findRepositoryRoot()
	if err != nil {
		return fmt.Errorf("finding repository root: %w", err)
	}
	return os.MkdirAll(filepath.Join(repositoryRoot, "build", "golang-crossbuild"), 0o770)
}

// CrossBuild cross-builds the beat for all target platforms.
func CrossBuild() error {
	mg.Deps(EnsureCrossBuildOutputDir)
	return devtools.CrossBuild()
}

// CrossBuildGoDaemon cross-builds the go-daemon binary using Docker.
func CrossBuildGoDaemon() error {
	mg.Deps(EnsureCrossBuildOutputDir)
	return devtools.CrossBuildGoDaemon()
}

// PackageAgentCore cross-builds and packages distribution artifacts containing
// only elastic-agent binaries with no extra files or dependencies.
func PackageAgentCore() {
	start := time.Now()
	defer func() { fmt.Println("packageAgentCore ran for", time.Since(start)) }()

	mg.Deps(CrossBuild, CrossBuildGoDaemon)

	devtools.UseElasticAgentCorePackaging()

	mg.Deps(devtools.Package)
}

// Config generates both the short/reference/docker.
func Config() {
	mg.Deps(configYML)
}

// ControlProto generates pkg/agent/control/proto module.
func ControlProto() error {
	if err := sh.RunV(
		"protoc",
		"--go_out=pkg/control/v2/cproto", "--go_opt=paths=source_relative",
		"--go-grpc_out=pkg/control/v2/cproto", "--go-grpc_opt=paths=source_relative",
		"control_v2.proto"); err != nil {
		return err
	}

	return sh.RunV(
		"protoc",
		"--go_out=pkg/control/v1/proto", "--go_opt=paths=source_relative",
		"--go-grpc_out=pkg/control/v1/proto", "--go-grpc_opt=paths=source_relative",
		"control_v1.proto")
}

func BuildPGP() error {
	// go run elastic-agent/dev-tools/cmd/buildpgp/build_pgp.go --in agent/spec/GPG-KEY-elasticsearch --out elastic-agent/pkg/release/pgp.go
	goF := filepath.Join("dev-tools", "cmd", "buildpgp", "build_pgp.go")
	in := "GPG-KEY-elasticsearch"
	out := filepath.Join("internal", "pkg", "release", "pgp.go")

	fmt.Printf(">> BuildPGP from %s to %s\n", in, out)
	return RunGo("run", goF, "--in", in, "--output", out)
}

func configYML() error {
	return devtools.Config(devtools.AllConfigTypes, ConfigFileParams(), ".")
}

// ConfigFileParams returns the parameters for generating OSS config.
func ConfigFileParams() devtools.ConfigFileParams {
	p := devtools.ConfigFileParams{
		Templates: []string{"_meta/config/*.tmpl"},
		Short: devtools.ConfigParams{
			Template: "_meta/config/elastic-agent.yml.tmpl",
		},
		Reference: devtools.ConfigParams{
			Template: "_meta/config/elastic-agent.reference.yml.tmpl",
		},
		Docker: devtools.ConfigParams{
			Template: "_meta/config/elastic-agent.docker.yml.tmpl",
		},
	}
	return p
}

// UnitTest performs unit test on agent.
func UnitTest() {
	mg.Deps(Test.All)
}

// BuildFleetCfg embed the default fleet configuration as part of the binary.
func BuildFleetCfg() error {
	goF := filepath.Join("dev-tools", "cmd", "buildfleetcfg", "buildfleetcfg.go")
	in := filepath.Join("_meta", "elastic-agent.fleet.yml")
	out := filepath.Join("internal", "pkg", "agent", "application", "configuration_embed.go")

	fmt.Printf(">> BuildFleetCfg %s to %s\n", in, out)
	return RunGo("run", goF, "--in", in, "--out", out)
}

// Enroll runs agent which enrolls before running.
func (Demo) Enroll(ctx context.Context) error {
	env := map[string]string{
		"FLEET_ENROLL": "1",
	}
	return runAgent(ctx, env)
}

// NoEnroll runs agent which does not enroll before running.
func (Demo) NoEnroll(ctx context.Context) error {
	env := map[string]string{
		"FLEET_ENROLL": "0",
	}
	return runAgent(ctx, env)
}

// Image builds a cloud image
func (Cloud) Image(ctx context.Context) {
	platforms := os.Getenv(platformsEnv)
	defer os.Setenv(platformsEnv, platforms)

	packages := os.Getenv(packagesEnv)
	defer os.Setenv(packagesEnv, packages)

	snapshot := os.Getenv(snapshotEnv)
	defer os.Setenv(snapshotEnv, snapshot)

	dev := os.Getenv(devEnv)
	defer os.Setenv(devEnv, dev)

	os.Setenv(platformsEnv, "linux/amd64")
	os.Setenv(packagesEnv, "docker")
	os.Setenv(devEnv, "true")

	if s, err := strconv.ParseBool(snapshot); err == nil && !s {
		// only disable SNAPSHOT build when explicitely defined
		os.Setenv(snapshotEnv, "false")
		devtools.Snapshot = false
	} else {
		os.Setenv(snapshotEnv, "true")
		devtools.Snapshot = true
	}

	devtools.DevBuild = true
	devtools.Platforms = devtools.Platforms.Filter("linux/amd64")
	devtools.SelectedPackageTypes = []devtools.PackageType{devtools.Docker}

	if _, hasExternal := os.LookupEnv(externalArtifacts); !hasExternal {
		devtools.ExternalBuild = true
	}

	Package(ctx)
}

// Push builds a cloud image tags it correctly and pushes to remote image repo.
// Previous login to elastic registry is required!
func (Cloud) Push() error {
	snapshot := os.Getenv(snapshotEnv)
	defer os.Setenv(snapshotEnv, snapshot)

	os.Setenv(snapshotEnv, "true")

	version := getVersion()
	var tag string
	if envTag, isPresent := os.LookupEnv("CUSTOM_IMAGE_TAG"); isPresent && len(envTag) > 0 {
		tag = envTag
	} else {
		commit := dockerCommitHash()
		time := time.Now().Unix()

		tag = fmt.Sprintf("%s-%s-%d", version, commit, time)
	}

	sourceCloudImageName := fmt.Sprintf("docker.elastic.co/beats-ci/elastic-agent-cloud:%s", version)
	var targetCloudImageName string
	if customImage, isPresent := os.LookupEnv("CI_ELASTIC_AGENT_DOCKER_IMAGE"); isPresent && len(customImage) > 0 {
		targetCloudImageName = fmt.Sprintf("%s:%s", customImage, tag)
	} else {
		targetCloudImageName = fmt.Sprintf(cloudImageTmpl, tag)
	}

	fmt.Printf(">> Setting a docker image tag to %s\n", targetCloudImageName)
	err := sh.RunV("docker", "tag", sourceCloudImageName, targetCloudImageName)
	if err != nil {
		return fmt.Errorf("Failed setting a docker image tag: %w", err)
	}
	fmt.Println(">> Docker image tag updated successfully")

	fmt.Println(">> Pushing a docker image to remote registry")
	err = sh.RunV("docker", "image", "push", targetCloudImageName)
	if err != nil {
		return fmt.Errorf("Failed pushing docker image: %w", err)
	}
	fmt.Printf(">> Docker image pushed to remote registry successfully: %s\n", targetCloudImageName)

	return nil
}

func Clean() {
	mg.Deps(devtools.Clean, Build.Clean)
}

func dockerCommitHash() string {
	commit, err := devtools.CommitHash()
	if err == nil && len(commit) > commitLen {
		return commit[:commitLen]
	}

	return ""
}

func getVersion() string {
	version, found := os.LookupEnv("BEAT_VERSION")
	if !found {
		version = bversion.GetDefaultVersion()
	}
	if !strings.Contains(version, "SNAPSHOT") {
		if _, ok := os.LookupEnv(snapshotEnv); ok {
			version += "-SNAPSHOT"
		}
	}

	return version
}

func runAgent(ctx context.Context, env map[string]string) error {
	prevPlatforms := os.Getenv("PLATFORMS")
	defer os.Setenv("PLATFORMS", prevPlatforms)

	// setting this improves build time
	os.Setenv("PLATFORMS", "+all linux/amd64")
	devtools.Platforms = devtools.NewPlatformList("+all linux/amd64")

	supportedEnvs := map[string]int{"FLEET_ENROLLMENT_TOKEN": 0, "FLEET_ENROLL": 0, "FLEET_SETUP": 0, "FLEET_TOKEN_NAME": 0, "KIBANA_HOST": 0, "KIBANA_PASSWORD": 0, "KIBANA_USERNAME": 0}

	tag := dockerTag()
	dockerImageOut, err := sh.Output("docker", "image", "ls")
	if err != nil {
		return err
	}

	// docker does not exists for this commit, build it
	if !strings.Contains(dockerImageOut, tag) {
		var dependenciesVersion string
		if beatVersion, found := os.LookupEnv("BEAT_VERSION"); !found {
			dependenciesVersion = bversion.GetDefaultVersion()
		} else {
			dependenciesVersion = beatVersion
		}

		// produce docker package
		packageAgent(ctx, []string{
			"linux/amd64",
		}, dependenciesVersion, nil, mg.F(devtools.UseElasticAgentDemoPackaging), mg.F(CrossBuild), devtools.SelectedPackageTypes)

		dockerPackagePath := filepath.Join("build", "package", "elastic-agent", "elastic-agent-linux-amd64.docker", "docker-build")
		if err := os.Chdir(dockerPackagePath); err != nil {
			return err
		}

		// build docker image
		if err := dockerBuild(tag); err != nil {
			fmt.Println(">> Building docker images again (after 10 seconds)")
			// This sleep is to avoid hitting the docker build issues when resources are not available.
			time.Sleep(10)
			if err := dockerBuild(tag); err != nil {
				return err
			}
		}
	}

	// prepare env variables
	envs := []string{
		// providing default kibana to be fixed for os-es if not provided
		"KIBANA_HOST=http://localhost:5601",
	}

	envs = append(envs, os.Environ()...)
	for k, v := range env {
		envs = append(envs, fmt.Sprintf("%s=%s", k, v))
	}

	// run docker cmd
	dockerCmdArgs := []string{"run", "--network", "host"}
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if _, isSupported := supportedEnvs[parts[0]]; !isSupported {
			continue
		}

		// fix value
		e = fmt.Sprintf("%s=%s", parts[0], fixOsEnv(parts[0], parts[1]))

		dockerCmdArgs = append(dockerCmdArgs, "-e", e)
	}

	dockerCmdArgs = append(dockerCmdArgs, tag)
	return sh.Run("docker", dockerCmdArgs...)
}

func packageAgent(ctx context.Context, platforms []string, dependenciesVersion string, manifestResponse *manifest.Build, agentPackaging, agentBinaryTarget mg.Fn, packageTypes []mage.PackageType) error {
	fmt.Println("--- Package Elastic-Agent")

	platformPackageSuffixes := []string{}
	for _, p := range platforms {
		platformPackageSuffixes = append(platformPackageSuffixes, manifest.PlatformPackages[p])
	}
	if mg.Verbose() {
		log.Printf("--- Packaging dependenciesVersion[%s], %+v \n", dependenciesVersion, platformPackageSuffixes)
	}

	// download/copy all the necessary dependencies for packaging elastic-agent
	archivePath, dropPath := collectPackageDependencies(platforms, dependenciesVersion, platformPackageSuffixes, packageTypes)

	// cleanup after build
	defer os.RemoveAll(archivePath)
	defer os.RemoveAll(dropPath)
	defer os.Unsetenv(agentDropPath)

	// create flat dir
	flatPath := filepath.Join(dropPath, ".elastic-agent_flat")
	if mg.Verbose() {
		log.Printf("--- creating flat dir in .elastic-agent_flat")
	}
	os.MkdirAll(flatPath, 0755)
	defer os.RemoveAll(flatPath)

	// extract all dependencies from their archives into flat dir
	flattenDependencies(platformPackageSuffixes, dependenciesVersion, archivePath, dropPath, flatPath, manifestResponse)

	// package agent
	log.Println("--- Running packaging function")
	mg.Deps(agentPackaging)

	log.Println("--- Running post packaging ")
	mg.Deps(Update)
	mg.Deps(agentBinaryTarget, CrossBuildGoDaemon)
	mg.SerialDeps(devtools.Package, TestPackages)
	return nil
}

// collectPackageDependencies performs the download (if it's an external dep), unpacking and move all the elastic-agent
// dependencies in the archivePath and dropPath
// NOTE: after the build is done the caller must:
// - delete archivePath and dropPath contents
// - unset AGENT_DROP_PATH environment variable
func collectPackageDependencies(platforms []string, packageVersion string, platformPackageSuffixes []string, packageTypes []mage.PackageType) (archivePath string, dropPath string) {
	dropPath, found := os.LookupEnv(agentDropPath)

	// try not to shadow too many variables
	var err error

	// build deps only when drop is not provided
	if !found || len(dropPath) == 0 {
		// prepare new drop
		dropPath = filepath.Join("build", "distributions", "elastic-agent-drop")
		dropPath, err = filepath.Abs(dropPath)
		if err != nil {
			panic(err)
		}

		if mg.Verbose() {
			log.Printf(">> Creating drop-in folder %+v \n", dropPath)
		}
		archivePath = movePackagesToArchive(dropPath, platformPackageSuffixes, packageVersion)

		if hasSnapshotEnv() {
			packageVersion = fmt.Sprintf("%s-SNAPSHOT", packageVersion)
		}

		os.Setenv(agentDropPath, dropPath)

		if devtools.ExternalBuild == true {

			// Only log fatal logs for logs produced. This is the global logger
			// used by github.com/elastic/elastic-agent/dev-tools/mage/downloads which can only be configured globally like this.
			//
			// Using FatalLevel avoids filling the build log with scary looking errors when we attempt to
			// download artifacts on unsupported platforms and choose to ignore the errors.
			//
			// Change this to InfoLevel to see exactly what the downloader is doing.
			downloads.LogLevel.Set(downloads.FatalLevel)

			errGroup, ctx := errgroup.WithContext(context.Background())
			completedDownloads := &atomic.Int32{}
			for _, spec := range manifest.ExpectedBinaries {
				for _, platform := range platforms {
					if !spec.SupportsPlatform(platform) {
						fmt.Printf("--- Binary %s does not support %s, download skipped\n", spec.BinaryName, platform)
						continue
					}
					for _, pkgType := range packageTypes {
						if !spec.SupportsPackageType(pkgcommon.PackageType(pkgType)) {
							continue
						}
						targetPath := filepath.Join(archivePath, manifest.PlatformPackages[platform])
						os.MkdirAll(targetPath, 0755)
						packageName := spec.GetPackageName(packageVersion, platform)
						errGroup.Go(downloadBinary(ctx, spec.ProjectName, packageName, spec.BinaryName, platform, packageVersion, targetPath, completedDownloads))
					}
				}
			}

			err = errGroup.Wait()
			if err != nil {
				panic(err)
			}
			if completedDownloads.Load() == 0 {
				panic(fmt.Sprintf("No packages were successfully downloaded. You may be building against an invalid or unreleased version. version=%s. If this is an unreleased version, try SNAPSHOT=true or EXTERNAL=false", packageVersion))
			}
		} else {
			packedBeats := []string{"agentbeat"}
			// build from local repo, will assume beats repo is located on the same root level
			for _, b := range packedBeats {
				pwd, err := filepath.Abs(filepath.Join("../beats/x-pack", b))
				if err != nil {
					panic(err)
				}

				packagesCopied := 0

				if !requiredPackagesPresent(pwd, b, packageVersion, platformPackageSuffixes) {
					fmt.Printf("--- Package %s\n", pwd)
					cmd := exec.Command("mage", "package")
					cmd.Dir = pwd
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Env = append(os.Environ(), fmt.Sprintf("PWD=%s", pwd), "AGENT_PACKAGING=on")
					if envVar := selectedPackageTypes(); envVar != "" {
						cmd.Env = append(cmd.Env, envVar)
					}

					if err := cmd.Run(); err != nil {
						panic(err)
					}
				}

				// copy to new drop
				sourcePath := filepath.Join(pwd, "build", "distributions")
				for _, rp := range platformPackageSuffixes {
					files, err := filepath.Glob(filepath.Join(sourcePath, "*"+rp+"*"))
					if err != nil {
						panic(err)
					}

					targetPath := filepath.Join(archivePath, rp)
					os.MkdirAll(targetPath, 0755)
					for _, f := range files {
						// safety check; if the user has an older version of the beats repo,
						// for example right after a release where you've `git pulled` from on repo and not the other,
						// they might end up with a mishmash of packages from different versions.
						// check to see if we have mismatched versions.
						if !strings.Contains(f, packageVersion) {
							// if this panic hits weird edge cases where we don't want actual failures, revert to a printf statement.
							panic(fmt.Sprintf("the file %s doesn't match agent version %s, beats repo might be out of date", f, packageVersion))
						}

						targetFile := filepath.Join(targetPath, filepath.Base(f))
						packagesCopied += 1
						if err := sh.Copy(targetFile, f); err != nil {
							panic(err)
						}
					}
				}
				// a very basic footcannon protector; if packages are missing and we need to rebuild them, check to see if those files were copied
				// if we needed to repackage beats but still somehow copied nothing, could indicate an issue. Usually due to beats and agent being at different versions.
				if packagesCopied == 0 {
					fmt.Println(">>> WARNING: no packages were copied, but we repackaged beats anyway. Check binary to see if intended beats are there.")
				}
			}
		}
	} else {
		archivePath = movePackagesToArchive(dropPath, platformPackageSuffixes, packageVersion)
	}
	return archivePath, dropPath
}

func removePythonWheels(matches []string, version string) []string {
	if hasSnapshotEnv() {
		version = fmt.Sprintf("%s-SNAPSHOT", version)
	}

	var wheels []string
	for _, spec := range manifest.ExpectedBinaries {
		if spec.PythonWheel {
			wheels = append(wheels, spec.GetPackageName(version, ""))
		}
	}

	cleaned := make([]string, 0, len(matches))
	for _, path := range matches {
		if !slices.Contains(wheels, filepath.Base(path)) {
			cleaned = append(cleaned, path)
		}
	}
	return cleaned
}

// flattenDependencies will extract all the required packages collected in archivePath and dropPath in flatPath and
// regenerate checksums
func flattenDependencies(requiredPackages []string, packageVersion, archivePath, dropPath, flatPath string, manifestResponse *manifest.Build) {
	for _, rp := range requiredPackages {
		targetPath := filepath.Join(archivePath, rp)
		versionedFlatPath := filepath.Join(flatPath, rp)
		versionedDropPath := filepath.Join(dropPath, rp)
		os.MkdirAll(targetPath, 0755)
		os.MkdirAll(versionedFlatPath, 0755)
		os.MkdirAll(versionedDropPath, 0755)

		// untar all
		matches, err := filepath.Glob(filepath.Join(targetPath, "*tar.gz"))
		if err != nil {
			panic(err)
		}
		zipMatches, err := filepath.Glob(filepath.Join(targetPath, "*zip"))
		if err != nil {
			panic(err)
		}
		matches = append(matches, zipMatches...)

		if mg.Verbose() {
			log.Printf("--- Unfiltered dependencies to flatten in %s : %v", targetPath, matches)
		}

		// never flatten any python wheels, the packages.yml and docker should handle
		// those specifically so that the python wheels are installed into the container
		matches = removePythonWheels(matches, packageVersion)

		if mg.Verbose() {
			log.Printf("--- Extracting into the flat dir: %v", matches)
		}

		for _, m := range matches {
			stat, err := os.Stat(m)
			if os.IsNotExist(err) {
				log.Printf("--- File %s not found: %v", m, err)
				continue
			} else if err != nil {
				panic(fmt.Errorf("failed stating file: %w", err))
			}

			if stat.IsDir() {
				continue
			}
			if mg.Verbose() {
				log.Printf(">>> Extracting %s to %s", m, versionedFlatPath)
			}

			if err := devtools.Extract(m, versionedFlatPath); err != nil {
				panic(err)
			}
		}

		checksums := make(map[string]string)
		// Operate on the files depending on if we're packaging from a manifest or not
		if manifestResponse != nil {
			checksums = devtools.ChecksumsWithManifest(rp, versionedFlatPath, versionedDropPath, manifestResponse)
		} else {
			checksums = devtools.ChecksumsWithoutManifest(versionedFlatPath, versionedDropPath, packageVersion)
		}

		if err := appendComponentChecksums(versionedDropPath, checksums); err != nil {
			panic(err)
		}
	}
}

// simple struct to deserialize branch information.
// When we remove snapshot API dependency this can go in the artifact api client code
type branchInfo struct {
	Version     string `json:"version"`
	BuildID     string `json:"build_id"`
	ManifestURL string `json:"manifest_url"`
	SummaryURL  string `json:"summary_url"`
}

// FetchLatestAgentCoreStagingDRA is a mage target that will retrieve the elastic-agent-core DRA artifacts and
// place them under build/dra/buildID. It accepts one argument that has to be a release branch present in staging DRA
func FetchLatestAgentCoreStagingDRA(ctx context.Context, branch string) error {
	branchInfo, err := findLatestBuildForBranch(ctx, baseURLForStagingDRA, branch)

	// Create a dir with the buildID at <root>/build/dra/<buildID>
	repositoryRoot, err := findRepositoryRoot()
	if err != nil {
		return fmt.Errorf("finding repository root: %w", err)
	}
	draDownloadDir := filepath.Join(repositoryRoot, "build", "dra")
	err = os.MkdirAll(draDownloadDir, 0o770)
	if err != nil {
		return fmt.Errorf("creating %q directory: %w", err)
	}

	artifacts, err := downloadDRAArtifacts(ctx, branchInfo.ManifestURL, draDownloadDir, agentCoreProjectName)
	if err != nil {
		return fmt.Errorf("downloading DRA artifacts from %q: %w", branchInfo.ManifestURL, err)
	}

	fmt.Println("Downloaded agent core DRAs:")
	for k := range artifacts {
		fmt.Println(k)
	}
	return nil
}

// PackageUsingDRA packages elastic-agent for distribution using Daily Released Artifacts specified in manifest.
func PackageUsingDRA(ctx context.Context) error {
	start := time.Now()
	defer func() { fmt.Println("package ran for", time.Since(start)) }()

	platforms := devtools.Platforms.Names()
	if len(platforms) == 0 {
		return fmt.Errorf("elastic-agent package is expected to build at least one platform package")
	}

	if !devtools.PackagingFromManifest {
		return fmt.Errorf("elastic-agent PackageUsingDRA is expected to build from a manifest. Check that %s is set to a manifest URL", devtools.ManifestUrlEnvVar)
	}

	manifestResponse, parsedVersion, err := downloadManifestAndSetVersion(ctx, devtools.ManifestURL)
	if err != nil {
		return fmt.Errorf("failed downloading manifest: %w", err)
	}

	// fix the commit hash independently of the current commit hash on the branch
	agentCoreProject, ok := manifestResponse.Projects[agentCoreProjectName]
	if !ok {
		return fmt.Errorf("%q project not found in manifest %q", agentCoreProjectName, devtools.ManifestURL)
	}
	err = os.Setenv(mage.AgentCommitHashEnvVar, agentCoreProject.CommitHash)
	if err != nil {
		return fmt.Errorf("setting agent commit hash %q: %w", agentCoreProject.CommitHash, err)
	}

	return packageAgent(ctx, platforms, parsedVersion.VersionWithPrerelease(), manifestResponse, mg.F(devtools.UseElasticAgentPackaging), mg.F(useDRAAgentBinaryForPackage, devtools.ManifestURL), devtools.SelectedPackageTypes)
}

func downloadManifestAndSetVersion(ctx context.Context, url string) (*manifest.Build, *version.ParsedSemVer, error) {
	resp, err := manifest.DownloadManifest(ctx, url)
	if err != nil {
		return nil, nil, fmt.Errorf("downloading manifest: %w", err)
	}

	parsedVersion, err := version.ParseVersion(resp.Version)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing manifest version %s: %w", resp.Version, err)
	}

	// When getting the packageVersion from snapshot we should also update the env of SNAPSHOT=true which is
	// something that we use as an implicit parameter to various functions
	if parsedVersion.IsSnapshot() {
		os.Setenv(snapshotEnv, "true")
		mage.Snapshot = true
	}
	os.Setenv("BEAT_VERSION", parsedVersion.CoreVersion())

	return &resp, parsedVersion, nil
}

func findRepositoryRoot() (string, error) {
	return sh.Output(mg.GoCmd(), "list", "-f", "{{.Root}}")
}

func findLatestBuildForBranch(ctx context.Context, baseURL string, branch string) (*branchInfo, error) {
	// latest build info for a branch is at "<base url>/latest/<branch>.json"
	branchLatestBuildUrl := strings.TrimSuffix(baseURL, "/") + fmt.Sprintf("/latest/%s.json", branch)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, branchLatestBuildUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("error composing request for finding latest build using %q: %w", branchLatestBuildUrl, err)
	}

	c := new(http.Client)
	resp, err := c.Do(request)
	if err != nil {
		return nil, fmt.Errorf("error fetching latest build using %q: %w", branchLatestBuildUrl, err)
	}
	if mg.Verbose() {
		log.Printf("Received response for %q : %+v", branchLatestBuildUrl, resp)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("bad HTTP status for GET %q: %d - %q", branchLatestBuildUrl, resp.StatusCode, resp.Status)
	}

	bi := new(branchInfo)
	// consume body
	err = json.NewDecoder(resp.Body).Decode(bi)
	if err != nil {
		return nil, fmt.Errorf("decoding json branch information: %w", err)
	}

	if mg.Verbose() {
		log.Printf("Received branch information for %q: %+v", branch, bi)
	}

	return bi, nil
}

func mapManifestPlatformToAgentPlatform(manifestPltf string) (string, bool) {
	mappings := map[string]string{
		"linux-x86_64":   "linux-amd64",
		"windows-x86_64": "windows-amd64",
		"darwin-x86_64":  "darwin-amd64",
		"darwin-aarch64": "darwin-arm64",
		"linux/x86_64":   "linux/amd64",
		"windows/x86_64": "windows/amd64",
		"darwin/x86_64":  "darwin/amd64",
		"darwin/aarch64": "darwin/arm64",
	}

	mappedPltf, found := mappings[manifestPltf]
	if !found {
		// default to the manifest platform if no mapping is found
		mappedPltf = manifestPltf
	}

	return mappedPltf, found
}

func filterPackagesByPlatform(pkgs map[string]manifest.Package) map[string]manifest.Package {
	if mg.Verbose() {
		log.Printf("unfiltered packages: %v", pkgs)
	}
	platforms := devtools.Platforms.Names()
	filteredPackages := map[string]manifest.Package{}
	for pkgName, pkgDesc := range pkgs {
		if mg.Verbose() {
			log.Printf("checking if %s:%v should be included", pkgName, pkgDesc)
		}
		for _, pkgOS := range pkgDesc.Os {
			platformString, _ := mapManifestPlatformToAgentPlatform(fmt.Sprintf("%s/%s", pkgOS, pkgDesc.Architecture))
			if slices.Contains(platforms, platformString) {
				if mg.Verbose() {
					log.Printf("platforms include %s", platformString)
				}
				filteredPackages[pkgName] = pkgDesc
				break
			}
		}
	}
	if mg.Verbose() {
		log.Printf("filtered packages: %v", filteredPackages)
	}
	return filteredPackages
}

func downloadDRAArtifacts(ctx context.Context, manifestUrl string, downloadDir string, projects ...string) (map[string]manifest.Package, error) {
	build, err := manifest.DownloadManifest(ctx, manifestUrl)
	if err != nil {
		return nil, fmt.Errorf("downloading manifest from %q: %w", manifestUrl, err)
	}

	// Create a dir with the buildID at <downloadDir>/<buildID>
	draDownloadDir := filepath.Join(downloadDir, build.BuildID)
	err = os.MkdirAll(draDownloadDir, 0o770)
	if err != nil {
		return nil, fmt.Errorf("creating %q directory: %w", err)
	}

	// sync access to the downloadedArtifacts map
	mx := new(sync.Mutex)
	downloadedArtifacts := map[string]manifest.Package{}
	errGrp, errCtx := errgroup.WithContext(ctx)

	for _, projectName := range projects {
		project, ok := build.Projects[projectName]
		if !ok {
			return nil, fmt.Errorf("project %q not found in manifest at %q", projectName, manifestUrl)
		}

		if mg.Verbose() {
			log.Printf("build %q project %s packages: %+v", build.BuildID, projectName, project)
		}
		// filter down the packages to the platforms we are building/support
		filteredPackages := filterPackagesByPlatform(project.Packages)
		if mg.Verbose() {
			log.Printf("packages to download: %v", filteredPackages)
		}
		for pkgName, pkgDesc := range filteredPackages {
			downloadFunc := func(pkgName string, pkgDesc manifest.Package) func() error {
				return func() error {
					artifactDownloadPath := filepath.Join(draDownloadDir, pkgName)
					err := manifest.DownloadPackage(errCtx, pkgDesc.URL, artifactDownloadPath)
					if err != nil {
						return fmt.Errorf("downloading %q: %w", pkgName, err)
					}

					// download the SHA to check integrity
					artifactSHADownloadPath := filepath.Join(draDownloadDir, pkgName+sha512FileExt)
					err = manifest.DownloadPackage(errCtx, pkgDesc.ShaURL, artifactSHADownloadPath)
					if err != nil {
						return fmt.Errorf("downloading SHA for %q: %w", pkgName, err)
					}

					err = download.VerifyChecksum(sha512.New(), artifactDownloadPath, artifactSHADownloadPath)
					if err != nil {
						return fmt.Errorf("validating checksum for %q: %w", pkgName, err)
					}

					// we should probably validate the signature, it can be done later as we return the package metadata
					// see https://github.com/elastic/elastic-agent/issues/4445

					mx.Lock()
					defer mx.Unlock()
					downloadedArtifacts[artifactDownloadPath] = pkgDesc

					return nil
				}
			}(pkgName, pkgDesc)

			errGrp.Go(downloadFunc)
		}
	}

	return downloadedArtifacts, errGrp.Wait()
}

func useDRAAgentBinaryForPackage(ctx context.Context, manifestUrl string) error {
	repositoryRoot, err := findRepositoryRoot()
	if err != nil {
		return fmt.Errorf("looking up for repository root: %w", err)
	}

	downloadDir := filepath.Join(repositoryRoot, "build", "dra")

	// fetch the agent-core DRA artifacts for the current branch
	artifacts, err := downloadDRAArtifacts(ctx, manifestUrl, downloadDir, agentCoreProjectName)
	if err != nil {
		return fmt.Errorf("downloading elastic-agent-core artifacts: %w", err)
	}

	mg.Deps(EnsureCrossBuildOutputDir)

	// place the artifacts where the package.yml expects them (in build/golang-crossbuild/{{.BeatName}}-{{.GOOS}}-{{.Platform.Arch}}{{.BinaryExt}})
	for artifactFile, artifactMeta := range artifacts {
		// uncompress the archive first
		const extractionSubdir = "extracted"
		extractDir := filepath.Join(filepath.Dir(artifactFile), extractionSubdir)
		err = devtools.Extract(artifactFile, extractDir)
		if err != nil {
			return fmt.Errorf("extracting %q: %w", artifactFile, err)
		}

		// we can take a shortcut as the archive contains a subdirectory with the same name of the file minus the extension
		// and we have to rename the binary file while moving using the same name
		artifactBaseFileName := filepath.Base(artifactFile)
		artifactBaseFileExt := filepath.Ext(artifactBaseFileName)
		if artifactBaseFileExt == ".gz" {
			// get the next extension to get .tar.gz if it's there
			artifactBaseFileExt = filepath.Ext(strings.TrimSuffix(artifactBaseFileName, artifactBaseFileExt)) + artifactBaseFileExt
		}

		// this is the directory name where we can find the agent executable
		targetArtifactName := strings.TrimSuffix(artifactBaseFileName, artifactBaseFileExt)
		const agentBinaryName = "elastic-agent"
		binaryExt := ""
		if slices.Contains(artifactMeta.Os, "windows") {
			binaryExt += ".exe"
		}
		srcBinaryPath := filepath.Join(extractDir, targetArtifactName, agentBinaryName+binaryExt)
		srcStat, err := os.Stat(srcBinaryPath)
		if err != nil {
			return fmt.Errorf("stat source binary name %q: %w", srcBinaryPath, err)
		}
		log.Printf("Source binary %q stat: %+v", srcBinaryPath, srcStat)

		dstPlatform, _ := mapManifestPlatformToAgentPlatform(fmt.Sprintf("%s-%s", artifactMeta.Os[0], artifactMeta.Architecture))
		dstFileName := fmt.Sprintf("elastic-agent-%s", dstPlatform) + binaryExt
		dstBinaryPath := filepath.Join(repositoryRoot, "build", "golang-crossbuild", dstFileName)

		log.Printf("copying %q to %q", srcBinaryPath, dstBinaryPath)

		err = copy.Copy(srcBinaryPath, dstBinaryPath, copy.Options{
			PermissionControl: copy.PerservePermission,
		})
		if err != nil {
			return fmt.Errorf("copying %q to %q: %w", srcBinaryPath, dstBinaryPath, err)
		}
	}
	return nil
}

// Helper that wraps the fetchBinaryFromArtifactsApi in a way that is compatible with the errgroup.Go() function.
// Ensures the arguments are captured by value before starting the goroutine.
func downloadBinary(ctx context.Context, project string, packageName string, binary string, platform string, version string, targetPath string, compl *atomic.Int32) func() error {
	return func() error {
		_, err := downloads.FetchProjectBinary(ctx, project, packageName, binary, version, 3, false, targetPath, true)
		if err != nil {
			return fmt.Errorf("FetchProjectBinary failed for %s on %s: %v", binary, platform, err)
		}

		compl.Add(1)
		fmt.Printf("Done downloading %s into %s\n", packageName, targetPath)
		return nil
	}
}

func appendComponentChecksums(versionedDropPath string, checksums map[string]string) error {
	// for each spec file checksum calculate binary checksum as well
	for file := range checksums {
		if !strings.HasSuffix(file, devtools.ComponentSpecFileSuffix) {
			continue
		}

		componentFile := strings.TrimSuffix(file, devtools.ComponentSpecFileSuffix)
		hash, err := devtools.GetSHA512Hash(filepath.Join(versionedDropPath, componentFile))
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf(">>> Computing hash for %q failed: file not present %w \n", componentFile, err)
			continue
		} else if err != nil {
			return err
		}

		checksums[componentFile] = hash
	}

	content, err := yamlChecksum(checksums)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(versionedDropPath, checksumFilename), content, 0644)
}

// movePackagesToArchive Create archive folder and move any pre-existing artifacts into it.
func movePackagesToArchive(dropPath string, platformPackageSuffixes []string, packageVersion string) string {
	archivePath := filepath.Join(dropPath, "archives")
	os.MkdirAll(archivePath, 0755)

	// move archives to archive path
	matches, err := filepath.Glob(filepath.Join(dropPath, "*tar.gz*"))
	if err != nil {
		panic(err)
	}
	zipMatches, err := filepath.Glob(filepath.Join(dropPath, "*zip*"))
	if err != nil {
		panic(err)
	}
	matches = append(matches, zipMatches...)

	for _, f := range matches {
		for _, packageSuffix := range platformPackageSuffixes {
			if mg.Verbose() {
				log.Printf("--- Evaluating moving dependency %s to archive path %s\n", f, archivePath)
			}
			// if the matched file name does not contain the platform suffix and it's not a platform-independent package, skip it
			if !strings.Contains(f, packageSuffix) && !isPlatformIndependentPackage(f, packageVersion) {
				if mg.Verbose() {
					log.Printf("--- Skipped moving dependency %s to archive path\n", f)
				}
				continue
			}

			stat, err := os.Stat(f)
			if os.IsNotExist(err) {
				continue
			} else if err != nil {
				panic(fmt.Errorf("failed stating file: %w", err))
			}

			if stat.IsDir() {
				continue
			}

			targetPath := filepath.Join(archivePath, packageSuffix, filepath.Base(f))
			targetDir := filepath.Dir(targetPath)
			if err := os.MkdirAll(targetDir, 0750); err != nil {
				fmt.Printf("warning: failed to create directory %s: %s", targetDir, err)
			}

			// Platform-independent packages need to be placed in the archive sub-folders for all platforms, copy instead of moving
			if isPlatformIndependentPackage(f, packageVersion) {
				if err := copyFile(f, targetPath); err != nil {
					panic(fmt.Errorf("failed copying file: %w", err))
				}
			} else {
				if err := os.Rename(f, targetPath); err != nil {
					panic(fmt.Errorf("failed renaming file: %w", err))
				}
			}

			if mg.Verbose() {
				log.Printf("--- Moved dependency in archive path %s => %s\n", f, targetPath)
			}
		}
	}

	return archivePath
}

func copyFile(src, dst string) error {
	srcStat, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat source file %q: %w", src, err)
	}

	srcF, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening source file %q: %w", src, err)
	}
	defer srcF.Close()

	dstF, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, srcStat.Mode()|os.ModePerm)
	if err != nil {
		return fmt.Errorf("opening/creating destination file %q: %w", dst, err)
	}
	defer dstF.Close()

	_, err = io.Copy(dstF, srcF)
	if err != nil {
		return fmt.Errorf("copying file %q to %q: %w", src, dst, err)
	}

	return nil
}

func isPlatformIndependentPackage(f string, packageVersion string) bool {
	fileBaseName := filepath.Base(f)
	for _, spec := range manifest.ExpectedBinaries {
		packageName := spec.GetPackageName(packageVersion, "")
		// as of now only python wheels packages are platform-independent
		if spec.PythonWheel && (fileBaseName == packageName || fileBaseName == packageName+sha512FileExt) {
			return true
		}
	}
	return false
}

func selectedPackageTypes() string {
	if len(devtools.SelectedPackageTypes) == 0 {
		return ""
	}

	return "PACKAGES=targz,zip"
}

func copyAll(from, to string, suffixes ...[]string) error {
	return filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		targetFile := filepath.Join(to, d.Name())

		// overwrites with current build
		return sh.Copy(targetFile, path)
	})
}

func dockerBuild(tag string) error {
	return sh.Run("docker", "build", "-t", tag, ".")
}

func dockerTag() string {
	tagBase := "elastic-agent"

	commit := dockerCommitHash()
	if len(commit) > 0 {
		return fmt.Sprintf("%s-%s", tagBase, commit)
	}

	return tagBase
}

func fixOsEnv(k, v string) string {
	switch k {
	case "KIBANA_HOST":
		// network host works in a weird way here
		if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
			return strings.Replace(strings.ToLower(v), "localhost", "host.docker.internal", 1)
		}
	}

	return v
}

func buildVars() map[string]string {
	vars := make(map[string]string)

	isSnapshot, _ := os.LookupEnv(snapshotEnv)
	vars["github.com/elastic/elastic-agent/internal/pkg/release.snapshot"] = isSnapshot

	if isDevFlag, devFound := os.LookupEnv(devEnv); devFound {
		if isDev, err := strconv.ParseBool(isDevFlag); err == nil && isDev {
			vars["github.com/elastic/elastic-agent/internal/pkg/release.allowEmptyPgp"] = "true"
			vars["github.com/elastic/elastic-agent/internal/pkg/release.allowUpgrade"] = "true"
		}
	}

	return vars
}

func injectBuildVars(m map[string]string) {
	for k, v := range buildVars() {
		m[k] = v
	}
}

func yamlChecksum(checksums map[string]string) ([]byte, error) {
	filesMap := make(map[string][]checksumFile)
	files := make([]checksumFile, 0, len(checksums))
	for file, checksum := range checksums {
		files = append(files, checksumFile{
			Name:     file,
			Checksum: checksum,
		})
	}

	filesMap["files"] = files
	return yaml.Marshal(filesMap)
}

type checksumFile struct {
	Name     string `yaml:"name"`
	Checksum string `yaml:"sha512"`
}

// Package packages elastic-agent for the IronBank distribution, relying on the
// binaries having already been built.
//
// Use SNAPSHOT=true to build snapshots.
func Ironbank() error {
	if runtime.GOARCH != "amd64" {
		fmt.Printf(">> IronBank images are only supported for amd64 arch (%s is not supported)\n", runtime.GOARCH)
		return nil
	}
	if err := prepareIronbankBuild(); err != nil {
		return fmt.Errorf("failed to prepare the IronBank context: %w", err)
	}
	if err := saveIronbank(); err != nil {
		return fmt.Errorf("failed to save artifacts for IronBank: %w", err)
	}
	return nil
}

func saveIronbank() error {
	fmt.Println(">> saveIronbank: save the IronBank container context.")

	ironbank := getIronbankContextName()
	buildDir := filepath.Join("build", ironbank)
	if _, err := os.Stat(buildDir); os.IsNotExist(err) {
		return fmt.Errorf("cannot find the folder with the ironbank context: %+v", err)
	}

	distributionsDir := "build/distributions"
	if _, err := os.Stat(distributionsDir); os.IsNotExist(err) {
		err := os.MkdirAll(distributionsDir, 0750)
		if err != nil {
			return fmt.Errorf("cannot create folder for docker artifacts: %+v", err)
		}
	}

	// change dir to the buildDir location where the ironbank folder exists
	// this will generate a tar.gz without some nested folders.
	wd, _ := os.Getwd()
	os.Chdir(buildDir)
	defer os.Chdir(wd)

	// move the folder to the parent folder, there are two parent folder since
	// buildDir contains a two folders dir.
	tarGzFile := filepath.Join("..", "..", distributionsDir, ironbank+".tar.gz")

	// Save the build context as tar.gz artifact
	err := devtools.Tar("./", tarGzFile)
	if err != nil {
		return fmt.Errorf("cannot compress the tar.gz file: %+v", err)
	}

	if err := devtools.CreateSHA512File(tarGzFile); err != nil {
		return fmt.Errorf("failed to create .sha512 file: %w", err)
	}

	return nil
}

func getIronbankContextName() string {
	version, _ := devtools.BeatQualifiedVersion()
	defaultBinaryName := "{{.Name}}-ironbank-{{.Version}}{{if .Snapshot}}-SNAPSHOT{{end}}"
	outputDir, _ := devtools.Expand(defaultBinaryName+"-docker-build-context", map[string]interface{}{
		"Name":    "elastic-agent",
		"Version": version,
	})
	return outputDir
}

func prepareIronbankBuild() error {
	fmt.Println(">> prepareIronbankBuild: prepare the IronBank container context.")
	buildDir := filepath.Join("build", getIronbankContextName())
	templatesDir := filepath.Join("dev-tools", "packaging", "templates", "ironbank")

	data := map[string]interface{}{
		"MajorMinor": majorMinor(),
	}

	err := filepath.WalkDir(templatesDir, func(path string, d fs.DirEntry, _ error) error {
		if !d.IsDir() {
			target := strings.TrimSuffix(
				filepath.Join(buildDir, filepath.Base(path)),
				".tmpl",
			)

			err := devtools.ExpandFile(path, target, data)
			if err != nil {
				return fmt.Errorf("expanding template '%s' to '%s': %w", path, target, err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cannot create templates for the IronBank: %+v", err)
	}

	// copy files
	sourcePath := filepath.Join("dev-tools", "packaging", "files", "ironbank")
	if err := devtools.Copy(sourcePath, buildDir); err != nil {
		return fmt.Errorf("cannot create files for the IronBank: %+v", err)
	}
	return nil
}

func majorMinor() string {
	if v, _ := devtools.BeatQualifiedVersion(); v != "" {
		parts := strings.SplitN(v, ".", 3)
		return parts[0] + "." + parts[1]
	}
	return ""
}

// Clean cleans up the integration testing leftovers
func (Integration) Clean() error {
	fmt.Println("--- Clean mage artifacts")
	_ = os.RemoveAll(".agent-testing")

	// Clean out .integration-cache/.ogc-cache always
	defer os.RemoveAll(".integration-cache")
	defer os.RemoveAll(".ogc-cache")

	_, err := os.Stat(".integration-cache")
	if err == nil {
		// .integration-cache exists; need to run `Clean` from the runner
		r, err := createTestRunner(false, "", "")
		if err != nil {
			return fmt.Errorf("error creating test runner: %w", err)
		}
		err = r.Clean()
		if err != nil {
			return fmt.Errorf("error running clean: %w", err)
		}
	}

	return nil
}

// Check checks that integration tests are using define.Require
func (Integration) Check() error {
	fmt.Println(">> check: Checking for define.Require in integration tests") // nolint:forbidigo // it's ok to use fmt.println in mage
	return define.ValidateDir("testing/integration")
}

// Local runs only the integration tests that support local mode
// it takes as argument the test name to run or all if we want to run them all.
func (Integration) Local(ctx context.Context, testName string) error {
	if shouldBuildAgent() {
		// need only local package for current platform
		devtools.Platforms = devtools.Platforms.Select(fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))
		mg.Deps(Package)
	}
	mg.Deps(Build.TestBinaries)

	// clean the .agent-testing/local so this run will use the latest build
	_ = os.RemoveAll(".agent-testing/local")

	// run the integration tests but only run test that can run locally
	params := devtools.DefaultGoTestIntegrationArgs()
	params.Tags = append(params.Tags, "local")
	params.Packages = []string{"github.com/elastic/elastic-agent/testing/integration"}

	var goTestFlags []string
	rawTestFlags := os.Getenv("GOTEST_FLAGS")
	if rawTestFlags != "" {
		goTestFlags = strings.Split(rawTestFlags, " ")
	}
	params.ExtraFlags = goTestFlags

	if testName == "all" {
		params.RunExpr = ""
	} else {
		params.RunExpr = testName
	}
	return devtools.GoTest(ctx, params)
}

// Auth authenticates users who run it to various IaaS CSPs and ESS
func (Integration) Auth(ctx context.Context) error {
	if err := authGCP(ctx); err != nil {
		return fmt.Errorf("unable to authenticate to GCP: %w", err)
	}
	fmt.Println("✔️  GCP authentication successful")

	// TODO: Authenticate user to AWS

	// TODO: Authenticate user to Azure

	if err := authESS(ctx); err != nil {
		return fmt.Errorf("unable to authenticate to ESS: %w", err)
	}
	fmt.Println("✔️  ESS authentication successful")

	return nil
}

// Test runs integration tests on remote hosts
func (Integration) Test(ctx context.Context) error {
	return integRunner(ctx, false, "")
}

// Matrix runs integration tests on a matrix of all supported remote hosts
func (Integration) Matrix(ctx context.Context) error {
	return integRunner(ctx, true, "")
}

// Single runs single integration test on remote host
func (Integration) Single(ctx context.Context, testName string) error {
	return integRunner(ctx, false, testName)
}

// Kubernetes runs kubernetes integration tests
func (Integration) Kubernetes(ctx context.Context) error {
	// invoke integration tests
	if err := os.Setenv("TEST_GROUPS", "kubernetes"); err != nil {
		return err
	}

	return integRunner(ctx, false, "")
}

// KubernetesMatrix runs a matrix of kubernetes integration tests
func (Integration) KubernetesMatrix(ctx context.Context) error {
	// invoke integration tests
	if err := os.Setenv("TEST_GROUPS", "kubernetes"); err != nil {
		return err
	}

	return integRunner(ctx, true, "")
}

// UpdateVersions runs an update on the `.agent-versions.yml` fetching
// the latest version list from the artifact API.
func (Integration) UpdateVersions(ctx context.Context) error {
	maxSnapshots := 3

	branches, err := git.GetReleaseBranches(ctx)
	if err != nil {
		return fmt.Errorf("failed to list release branches: %w", err)
	}

	// -1 because we manually add 7.17 below
	if len(branches) > maxSnapshots-1 {
		branches = branches[:maxSnapshots-1]
	}

	// it's not a part of this repository, cannot be retrieved with `GetReleaseBranches`
	branches = append(branches, "7.17")

	// uncomment if want to have the current version snapshot on the list as well
	// branches = append([]string{"master"}, branches...)

	reqs := upgradetest.VersionRequirements{
		UpgradeToVersion: bversion.Agent,
		CurrentMajors:    1,
		PreviousMinors:   2,
		PreviousMajors:   1,
		SnapshotBranches: branches,
	}
	b, _ := json.MarshalIndent(reqs, "", "  ")
	fmt.Println(string(b))

	pvc := pv.NewProductVersionsClient()
	sc := snapshots.NewSnapshotsClient()
	versions, err := upgradetest.FetchUpgradableVersions(ctx, pvc, sc, reqs)
	if err != nil {
		return fmt.Errorf("failed to fetch upgradable versions: %w", err)
	}
	versionFileData := upgradetest.AgentVersions{
		TestVersions: versions,
	}
	file, err := os.OpenFile(upgradetest.AgentVersionsFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open %s for write: %w", upgradetest.AgentVersionsFilename, err)
	}
	defer file.Close()

	// Write header
	header := "# This file is generated automatically. Please do not manually edit it.\n\n" +
		"# The testVersions list in this file specifies Elastic Agent versions to be used as\n" +
		"# the starting (pre-upgrade) or ending (post-upgrade) versions of Elastic Agent in\n" +
		"# upgrade integration tests.\n\n"

	io.WriteString(file, header)

	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	err = encoder.Encode(versionFileData)
	if err != nil {
		return fmt.Errorf("failed to encode YAML to file %s: %w", upgradetest.AgentVersionsFilename, err)
	}
	return nil
}

// UpdatePackageVersion update the file that contains the latest available snapshot version
func (Integration) UpdatePackageVersion(ctx context.Context) error {
	const packageVersionFilename = ".package-version"

	currentReleaseBranch, err := git.GetCurrentReleaseBranch(ctx)
	if err != nil {
		return fmt.Errorf("failed to identify the current release branch: %w", err)
	}

	sc := snapshots.NewSnapshotsClient()
	versions, err := sc.FindLatestSnapshots(ctx, []string{currentReleaseBranch})
	if err != nil {
		return fmt.Errorf("failed to fetch a manifest for the latest snapshot: %w", err)
	}
	if len(versions) != 1 {
		return fmt.Errorf("expected a single version, got %v", versions)
	}
	packageVersion := versions[0].CoreVersion()
	file, err := os.OpenFile(packageVersionFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open %s for write: %w", packageVersionFilename, err)
	}
	defer file.Close()
	_, err = file.WriteString(packageVersion)
	if err != nil {
		return fmt.Errorf("failed to write the package version file %s: %w", packageVersionFilename, err)
	}

	fmt.Println(packageVersion)

	return nil
}

var (
	stateDir  = ".integration-cache"
	stateFile = "state.yml"
)

// readFrameworkState reads the state file from the integration test framework
func readFrameworkState() (runner.State, error) {
	stateFilePath := ".integration-cache/state.yml"
	data, err := os.ReadFile(stateFilePath)
	if err != nil {
		return runner.State{}, fmt.Errorf("could not read state file %q: %w", stateFilePath, err)
	}

	state := runner.State{}
	if err := yaml.Unmarshal(data, &state); err != nil {
		return runner.State{}, fmt.Errorf("failed unmarshal state file %s: %w", stateFilePath, err)
	}

	return state, nil
}

func listInstances() (string, []runner.StateInstance, error) {
	builder := strings.Builder{}
	state, err := readFrameworkState()
	if err != nil {
		return "", []runner.StateInstance{}, fmt.Errorf("could not read state file: %w", err)
	}

	absStateDir, err := filepath.Abs(stateDir)
	if err != nil {
		return "", []runner.StateInstance{}, fmt.Errorf("cannot get absolute path from state directory '%s': %w", stateDir, err)
	}

	for i, vm := range state.Instances {
		isGCP := vm.Provisioner != "multipass"

		t := table.NewWriter()
		t.AppendRows([]table.Row{
			{"#", i},
			{"Provisioner", vm.Provisioner},
			{"Name", vm.Name},
			{"ID", vm.ID},
		})

		if isGCP {
			t.AppendRow(table.Row{"Instance ID", vm.Internal["instance_id"]})
		}

		t.AppendRows([]table.Row{
			{"IP", vm.IP},
			{"Private Key", filepath.Join(absStateDir, "id_rsa")},
			{"Public Key", filepath.Join(absStateDir, "id_rsa.pub")},
			{"SSH connection", fmt.Sprintf(`ssh -i %s %s@%s`, filepath.Join(absStateDir, "id_rsa"), vm.Username, vm.IP)},
		})

		if isGCP {
			t.AppendRow(table.Row{"GCP Link", fmt.Sprintf("https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/%s", vm.Internal["instance_id"])})
		}

		builder.WriteString(t.Render())
		builder.WriteString("\n")
	}

	return builder.String(), state.Instances, nil
}

func listStacks() (string, error) {
	builder := strings.Builder{}

	state, err := readFrameworkState()
	if err != nil {
		return "", fmt.Errorf("could not read state file: %w", err)
	}

	for i, stack := range state.Stacks {
		t := table.NewWriter()
		t.AppendRows([]table.Row{
			{"#", i},
			{"Type", stack.Provisioner},
		})

		switch {
		case stack.Provisioner == "serverless":
			t.AppendRow(table.Row{"Project ID", stack.Internal["deployment_id"]})
		case stack.Provisioner == "stateful":
			t.AppendRow(table.Row{"Deployment ID", stack.Internal["deployment_id"]})
		}
		t.AppendRows([]table.Row{
			{"Elasticsearch URL", stack.Elasticsearch},
			{"Kibana", stack.Kibana},
			{"Username", stack.Username},
			{"Password", stack.Password},
		})
		builder.WriteString(t.Render())
		builder.WriteString("\n")
	}

	return builder.String(), nil
}

func askForVM() (runner.StateInstance, error) {
	vms, instances, err := listInstances()
	if err != nil {
		fmt.Errorf("cannot list VMs: %w", err)
	}
	fmt.Fprintf(os.Stderr, vms)

	if len(instances) == 1 {
		fmt.Fprintln(os.Stderr, "There is only one VM, auto-selecting it")
		return instances[0], nil
	}

	id := 0
	fmt.Fprint(os.Stderr, "Instance number: ")
	if _, err := fmt.Scanf("%d", &id); err != nil {
		return runner.StateInstance{}, fmt.Errorf("could not read instance number: %w:", err)
	}

	if id >= len(instances) {
		return runner.StateInstance{}, fmt.Errorf("Invalid Stack number, it must be between 0 and %d", len(instances)-1)
	}

	return instances[id], nil
}

func askForStack() (tcommon.Stack, error) {
	mg.Deps(Integration.Stacks)

	state, err := readFrameworkState()
	if err != nil {
		return tcommon.Stack{}, fmt.Errorf("could not read state file: %w", err)
	}

	if len(state.Stacks) == 1 {
		fmt.Println("There is only one Stack, auto-selecting it")
		return state.Stacks[0], nil
	}

	id := 0
	fmt.Print("Stack number: ")
	if _, err := fmt.Scanf("%d", &id); err != nil {
		return tcommon.Stack{}, fmt.Errorf("cannot read Stack number: %w", err)
	}

	if id >= len(state.Stacks) {
		return tcommon.Stack{}, fmt.Errorf("Invalid Stack number, it must be between 0 and %d", len(state.Stacks)-1)
	}

	return state.Stacks[id], nil
}

func generateEnvFile(stack tcommon.Stack) error {
	fileExists := true
	stat, err := os.Stat("./env.sh")
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cannot stat 'env.sh': %w", err)
		}
		fileExists = false
	}

	if fileExists {
		bkpName := fmt.Sprintf("./env.sh-%d", rand.Int())
		if err := os.Rename(stat.Name(), bkpName); err != nil {
			return fmt.Errorf("cannot create backup: %w", err)
		}
		fmt.Printf("%q already existed, it was moved to %q\n", stat.Name(), bkpName)
	}

	f, err := os.Create("./env.sh")
	if err != nil {
		return fmt.Errorf("Could not create './env.sh': %w", err)
	}
	defer f.Close()

	fmt.Fprintf(f, "export ELASTICSEARCH_HOST=\"%s\"\n", stack.Elasticsearch)
	fmt.Fprintf(f, "export ELASTICSEARCH_USERNAME=\"%s\"\n", stack.Username)
	fmt.Fprintf(f, "export ELASTICSEARCH_PASSWORD=\"%s\"\n", stack.Password)

	fmt.Fprintf(f, "export KIBANA_HOST=\"%s\"\n", stack.Kibana)
	fmt.Fprintf(f, "export KIBANA_USERNAME=\"%s\"\n", stack.Username)
	fmt.Fprintf(f, "export KIBANA_PASSWORD=\"%s\"\n", stack.Password)

	return nil
}

// PrintState prints details about cloud stacks and VMs
func (Integration) PrintState(ctx context.Context) {
	fmt.Println("Virtual Machines")
	mg.Deps(Integration.ListInstances)
	fmt.Print("\n\n")
	fmt.Println("Cloud Stacks")
	mg.Deps(Integration.Stacks)
}

// ListInstances lists all VMs in a human readable form, including connection details
func (Integration) ListInstances() error {
	t, _, err := listInstances()
	if err != nil {
		fmt.Errorf("cannot list VMs: %w", err)
	}

	fmt.Print(t)

	return nil
}

// SSH prints to stdout the SSH command to connect to a VM, a menu is printed to stderr.
func (Integration) SSH() error {
	absStateDir, err := filepath.Abs(stateDir)
	if err != nil {
		return fmt.Errorf("cannot get absolute path from state directory '%s': %w", stateDir, err)
	}

	vm, err := askForVM()
	if err != nil {
		fmt.Errorf("cannot get VM: %w", err)
	}

	fmt.Println(fmt.Sprintf(`ssh -i %s %s@%s`, filepath.Join(absStateDir, "id_rsa"), vm.Username, vm.IP))
	return nil
}

// Stacks lists all stack deployments in a human readable form
func (Integration) Stacks() error {
	stacks, err := listStacks()
	if err != nil {
		return fmt.Errorf("cannot list stacks: %w", err)
	}

	fmt.Print(stacks)
	return nil
}

// GenerateEnvFile generates 'env.sh' containing envvars to connect to a cloud stack
func (Integration) GenerateEnvFile() error {
	stack, err := askForStack()
	if err != nil {
		return fmt.Errorf("cannot get stack: %w", err)
	}

	if err := generateEnvFile(stack); err != nil {
		return fmt.Errorf("cannot generate env file: %w", err)
	}
	fmt.Println("run 'source ./env.sh' to load the environment variables to your shell")

	return nil
}

// DeployEnvFile generates and deploys to a VM 'env.sh' containing envvars to connect to a cloud stack
func (Integration) DeployEnvFile() error {
	stack, err := askForStack()
	if err != nil {
		return fmt.Errorf("cannot get stack: %w", err)
	}

	if err := generateEnvFile(stack); err != nil {
		return fmt.Errorf("cannot generate env file: %w", err)
	}

	fullEnvFilepath, err := filepath.Abs("./env.sh")
	if err != nil {
		return fmt.Errorf("cannot get full filepath for env file: %w", err)
	}

	absStateDir, err := filepath.Abs(stateDir)
	if err != nil {
		return fmt.Errorf("cannot get absolute path from state directory '%s': %w", stateDir, err)
	}
	keyFile := filepath.Join(absStateDir, "id_rsa")

	vm, err := askForVM()
	if err != nil {
		return fmt.Errorf("cannot get VM: %w", err)
	}

	cmd := exec.Command("scp", "-i", keyFile, fullEnvFilepath, fmt.Sprintf("%s@%s:~/env.sh", vm.Username, vm.IP))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not copy env file to VM: %w", err)
	}

	return nil
}

// DeployDebugTools installs all necessary tools to debug tests from a VM
func (Integration) DeployDebugTools() error {
	absStateDir, err := filepath.Abs(stateDir)
	if err != nil {
		return fmt.Errorf("cannot get absolute path from state directory '%s': %w", stateDir, err)
	}
	keyFile := filepath.Join(absStateDir, "id_rsa")

	vm, err := askForVM()
	if err != nil {
		return fmt.Errorf("cannot get VM: %w", err)
	}

	isWindowsVM := strings.Contains(vm.ID, "windows")

	commands := []string{
		fmt.Sprintf("sudo chown -R %s:%s $HOME/go/pkg", vm.Username, vm.Username),
		"go install github.com/go-delve/delve/cmd/dlv@latest",
	}

	if isWindowsVM {
		commands = append(commands,
			"choco install -y git",
			"if exist mage rmdir /s /q mage",
			"if exist elastic-agent rmdir /s /q elastic-agent",
		)
	} else {
		commands = append(commands,
			`echo 'export PATH=$PATH:'"$HOME/go/bin" |sudo tee /root/.bashrc`,
			"rm -rf mage",
			"rm -rf elastic-agent",
			"sudo apt install -y docker.io",
			"sudo systemctl enable --now docker",
			"sudo usermod -aG docker $USER",
		)
	}

	commands = append(commands,
		"git clone https://github.com/magefile/mage",
		"cd mage && go run bootstrap.go",
		"git clone https://github.com/elastic/elastic-agent",
	)

	if isWindowsVM {
		commands = append(commands, "cd elastic-agent && xcopy /s /e /y ..\\agent\\ .\\")
	} else {
		commands = append(commands, "cd elastic-agent && cp -r ~/agent/* ./")
	}

	for _, c := range commands {
		cmd := exec.Command("ssh", "-i", keyFile, fmt.Sprintf("%s@%s", vm.Username, vm.IP), c)
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout

		if err := cmd.Run(); err != nil {
			return err
		}
	}

	fmt.Println("Delve, Mage have been installed and added to the path")
	fmt.Println("~/elastic-agent")
	return nil
}

// PrepareOnRemote shouldn't be called locally (called on remote host to prepare it for testing)
func (Integration) PrepareOnRemote() {
	mg.Deps(mage.InstallGoTestTools)
}

// Run beat serverless tests
func (Integration) TestBeatServerless(ctx context.Context, beatname string) error {
	beatBuildPath := filepath.Join("..", "beats", "x-pack", beatname, "build", "distributions")
	if os.Getenv("AGENT_BUILD_DIR") == "" {
		err := os.Setenv("AGENT_BUILD_DIR", beatBuildPath)
		if err != nil {
			return fmt.Errorf("error setting build dir: %s", err)
		}
	}

	// a bit of bypass logic; run as serverless by default
	if os.Getenv("STACK_PROVISIONER") == "" {
		err := os.Setenv("STACK_PROVISIONER", "serverless")
		if err != nil {
			return fmt.Errorf("error setting serverless stack var: %w", err)
		}
	} else if os.Getenv("STACK_PROVISIONER") == "stateful" {
		fmt.Printf(">>> Warning: running TestBeatServerless as stateful\n")
	}

	err := os.Setenv("TEST_BINARY_NAME", beatname)
	if err != nil {
		return fmt.Errorf("error setting binary name: %w", err)
	}
	return integRunner(ctx, false, "TestBeatsServerless")
}

func (Integration) TestForResourceLeaks(ctx context.Context) error {
	err := os.Setenv("TEST_LONG_RUNNING", "true")
	if err != nil {
		return fmt.Errorf("error setting TEST_LONG_RUNNING: %w", err)
	}
	return integRunner(ctx, false, "TestLongRunningAgentForLeaks")
}

// TestOnRemote shouldn't be called locally (called on remote host to perform testing)
func (Integration) TestOnRemote(ctx context.Context) error {
	mg.Deps(Build.TestBinaries)
	version := os.Getenv("AGENT_VERSION")
	if version == "" {
		return errors.New("AGENT_VERSION environment variable must be set")
	}
	prefix := os.Getenv("TEST_DEFINE_PREFIX")
	if prefix == "" {
		return errors.New("TEST_DEFINE_PREFIX environment variable must be set")
	}
	testsStr := os.Getenv("TEST_DEFINE_TESTS")
	if testsStr == "" {
		return errors.New("TEST_DEFINE_TESTS environment variable must be set")
	}

	var goTestFlags []string
	rawTestFlags := os.Getenv("GOTEST_FLAGS")
	if rawTestFlags != "" {
		goTestFlags = strings.Split(rawTestFlags, " ")
	}

	tests := strings.Split(testsStr, ",")
	testsByPackage := make(map[string][]string)
	for _, testStr := range tests {
		testsStrSplit := strings.SplitN(testStr, ":", 2)
		if len(testsStrSplit) != 2 {
			return fmt.Errorf("%s is malformated it should be in the format of ${package}:${test_name}", testStr)
		}
		testsForPackage := testsByPackage[testsStrSplit[0]]
		testsForPackage = append(testsForPackage, testsStrSplit[1])
		testsByPackage[testsStrSplit[0]] = testsForPackage
	}
	smallPackageNames := make(map[string]string)
	for packageName := range testsByPackage {
		smallName := filepath.Base(packageName)
		existingPackage, ok := smallPackageNames[smallName]
		if ok {
			return fmt.Errorf("%s package collides with %s, because the base package name is the same", packageName, existingPackage)
		} else {
			smallPackageNames[smallName] = packageName
		}
	}
	for packageName, packageTests := range testsByPackage {
		testPrefix := fmt.Sprintf("%s.%s", prefix, filepath.Base(packageName))
		testName := fmt.Sprintf("remote-%s", testPrefix)
		fileName := fmt.Sprintf("build/TEST-go-%s", testName)
		extraFlags := make([]string, 0, len(goTestFlags)+6)
		if len(goTestFlags) > 0 {
			extraFlags = append(extraFlags, goTestFlags...)
		}
		extraFlags = append(extraFlags, "-test.shuffle", "on",
			"-test.timeout", goIntegTestTimeout.String(), "-test.run", "^("+strings.Join(packageTests, "|")+")$")
		params := mage.GoTestArgs{
			LogName:         testName,
			OutputFile:      fileName + ".out",
			JUnitReportFile: fileName + ".xml",
			Packages:        []string{packageName},
			Tags:            []string{"integration"},
			ExtraFlags:      extraFlags,
			Env: map[string]string{
				"AGENT_VERSION":      version,
				"TEST_DEFINE_PREFIX": testPrefix,
			},
		}
		err := devtools.GoTest(ctx, params)
		if err != nil {
			return err
		}
	}
	return nil
}

func (Integration) Buildkite() error {
	goTestFlags := os.Getenv("GOTEST_FLAGS")
	batches, err := define.DetermineBatches("testing/integration", goTestFlags, "integration")
	if err != nil {
		return fmt.Errorf("failed to determine batches: %w", err)
	}
	agentVersion, agentStackVersion, err := getTestRunnerVersions()
	if err != nil {
		return fmt.Errorf("failed to get agent versions: %w", err)
	}
	goVersion, err := mage.DefaultBeatBuildVariableSources.GetGoVersion()
	if err != nil {
		return fmt.Errorf("failed to get go versions: %w", err)
	}

	cfg := tcommon.Config{
		AgentVersion: agentVersion,
		StackVersion: agentStackVersion,
		GOVersion:    goVersion,
		Platforms:    testPlatforms(),
		Packages:     testPackages(),
		Groups:       testGroups(),
		Matrix:       false,
		VerboseMode:  mg.Verbose(),
		TestFlags:    goTestFlags,
	}

	steps, err := buildkite.GenerateSteps(cfg, batches...)
	if err != nil {
		return fmt.Errorf("error generating buildkite steps: %w", err)
	}

	// write output to steps.yaml
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting current working directory: %w", err)
	}
	ymlFilePath := filepath.Join(cwd, "steps.yml")
	file, err := os.Create(ymlFilePath)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()
	if _, err := file.WriteString(steps); err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	fmt.Printf(">>> Generated buildkite steps written to: %s\n", ymlFilePath)
	return nil
}

func integRunner(ctx context.Context, matrix bool, singleTest string) error {
	if _, ok := ctx.Deadline(); !ok {
		// If the context doesn't have a timeout (usually via the mage -t option), give it one.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, goProvisionAndTestTimeout)
		defer cancel()
	}

	for {
		failedCount, err := integRunnerOnce(ctx, matrix, singleTest)
		if err != nil {
			return err
		}
		if failedCount > 0 {
			if hasCleanOnExit() {
				mg.Deps(Integration.Clean)
			}
			os.Exit(1)
		}
		if !hasRunUntilFailure() {
			if hasCleanOnExit() {
				mg.Deps(Integration.Clean)
			}
			return nil
		}
	}
}

func integRunnerOnce(ctx context.Context, matrix bool, singleTest string) (int, error) {
	goTestFlags := os.Getenv("GOTEST_FLAGS")

	batches, err := define.DetermineBatches("testing/integration", goTestFlags, "integration")
	if err != nil {
		return 0, fmt.Errorf("failed to determine batches: %w", err)
	}
	r, err := createTestRunner(matrix, singleTest, goTestFlags, batches...)
	if err != nil {
		return 0, fmt.Errorf("error creating test runner: %w", err)
	}
	results, err := r.Run(ctx)
	if err != nil {
		return 0, fmt.Errorf("error running test: %w", err)
	}
	_ = os.Remove("build/TEST-go-integration.out")
	_ = os.Remove("build/TEST-go-integration.out.json")
	_ = os.Remove("build/TEST-go-integration.xml")
	err = writeFile("build/TEST-go-integration.out", results.Output, 0644)
	if err != nil {
		return 0, fmt.Errorf("error writing test out file: %w", err)
	}
	err = writeFile("build/TEST-go-integration.out.json", results.JSONOutput, 0644)
	if err != nil {
		return 0, fmt.Errorf("error writing test out json file: %w", err)
	}
	err = writeFile("build/TEST-go-integration.xml", results.XMLOutput, 0644)
	if err != nil {
		return 0, fmt.Errorf("error writing test out xml file: %w", err)
	}
	if results.Failures > 0 {
		r.Logger().Logf("Testing completed (%d failures, %d successful)", results.Failures, results.Tests-results.Failures)
	} else {
		r.Logger().Logf("Testing completed (%d successful)", results.Tests)
	}
	r.Logger().Logf("Console output written here: build/TEST-go-integration.out")
	r.Logger().Logf("Console JSON output written here: build/TEST-go-integration.out.json")
	r.Logger().Logf("JUnit XML written here: build/TEST-go-integration.xml")
	r.Logger().Logf("Diagnostic output (if present) here: build/diagnostics")
	return results.Failures, nil
}

func getTestRunnerVersions() (string, string, error) {
	var err error
	agentStackVersion := os.Getenv("AGENT_STACK_VERSION")
	agentVersion := os.Getenv("AGENT_VERSION")
	if agentVersion == "" {
		agentVersion, err = mage.DefaultBeatBuildVariableSources.GetBeatVersion()
		if err != nil {
			return "", "", err
		}
		if agentStackVersion == "" {
			// always use snapshot for stack version
			agentStackVersion = fmt.Sprintf("%s-SNAPSHOT", agentVersion)
		}
		if hasSnapshotEnv() {
			// in the case that SNAPSHOT=true is set in the environment the
			// default version of the agent is used, but as a snapshot build
			agentVersion = fmt.Sprintf("%s-SNAPSHOT", agentVersion)
		}
	}

	if agentStackVersion == "" {
		agentStackVersion = agentVersion
	}

	return agentVersion, agentStackVersion, nil
}

func createTestRunner(matrix bool, singleTest string, goTestFlags string, batches ...define.Batch) (*runner.Runner, error) {
	goVersion, err := mage.DefaultBeatBuildVariableSources.GetGoVersion()
	if err != nil {
		return nil, err
	}

	agentVersion, agentStackVersion, err := getTestRunnerVersions()
	if err != nil {
		return nil, err
	}

	agentBuildDir := os.Getenv("AGENT_BUILD_DIR")
	if agentBuildDir == "" {
		agentBuildDir = filepath.Join("build", "distributions")
	}
	essToken, ok, err := ess.GetESSAPIKey()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("ESS api key missing; run 'mage integration:auth'")
	}

	// Possible to change the region for deployment, default is gcp-us-west2 which is
	// the CFT region.
	essRegion := os.Getenv("TEST_INTEG_AUTH_ESS_REGION")
	if essRegion == "" {
		essRegion = "gcp-us-west2"
	}

	serviceTokenPath, ok, err := getGCEServiceTokenPath()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("GCE service token missing; run 'mage integration:auth'")
	}
	datacenter := os.Getenv("TEST_INTEG_AUTH_GCP_DATACENTER")
	if datacenter == "" {
		// us-central1-a is used because T2A instances required for ARM64 testing are only
		// available in the central regions
		datacenter = "us-central1-a"
	}

	ogcCfg := ogc.Config{
		ServiceTokenPath: serviceTokenPath,
		Datacenter:       datacenter,
	}

	var instanceProvisioner tcommon.InstanceProvisioner
	instanceProvisionerMode := os.Getenv("INSTANCE_PROVISIONER")
	switch instanceProvisionerMode {
	case "", ogc.Name:
		instanceProvisionerMode = ogc.Name
		instanceProvisioner, err = ogc.NewProvisioner(ogcCfg)
	case multipass.Name:
		instanceProvisioner = multipass.NewProvisioner()
	case kind.Name:
		instanceProvisioner = kind.NewProvisioner()
	default:
		return nil, fmt.Errorf("INSTANCE_PROVISIONER environment variable must be one of 'ogc' or 'multipass', not %s", instanceProvisionerMode)
	}

	email, err := ogcCfg.ClientEmail()
	if err != nil {
		return nil, err
	}

	provisionCfg := ess.ProvisionerConfig{
		Identifier: fmt.Sprintf("at-%s", strings.Replace(strings.Split(email, "@")[0], ".", "-", -1)),
		APIKey:     essToken,
		Region:     essRegion,
	}

	var stackProvisioner tcommon.StackProvisioner
	stackProvisionerMode := os.Getenv("STACK_PROVISIONER")
	switch stackProvisionerMode {
	case "", ess.ProvisionerStateful:
		stackProvisionerMode = ess.ProvisionerStateful
		stackProvisioner, err = ess.NewProvisioner(provisionCfg)
		if err != nil {
			return nil, err
		}
	case ess.ProvisionerServerless:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		stackProvisioner, err = ess.NewServerlessProvisioner(ctx, provisionCfg)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("STACK_PROVISIONER environment variable must be one of %q or %q, not %s",
			ess.ProvisionerStateful,
			ess.ProvisionerServerless,
			stackProvisionerMode)
	}

	timestamp := timestampEnabled()

	extraEnv := map[string]string{}
	if agentCollectDiag := os.Getenv("AGENT_COLLECT_DIAG"); agentCollectDiag != "" {
		extraEnv["AGENT_COLLECT_DIAG"] = agentCollectDiag
	}
	if agentKeepInstalled := os.Getenv("AGENT_KEEP_INSTALLED"); agentKeepInstalled != "" {
		extraEnv["AGENT_KEEP_INSTALLED"] = agentKeepInstalled
	}

	extraEnv["TEST_LONG_RUNNING"] = os.Getenv("TEST_LONG_RUNNING")
	extraEnv["LONG_TEST_RUNTIME"] = os.Getenv("LONG_TEST_RUNTIME")

	// these following two env vars are currently not used by anything, but can be used in the future to test beats or
	// other binaries, see https://github.com/elastic/elastic-agent/pull/3258
	binaryName := os.Getenv("TEST_BINARY_NAME")
	if binaryName == "" {
		binaryName = "elastic-agent"
	}

	repoDir := os.Getenv("TEST_INTEG_REPO_PATH")
	if repoDir == "" {
		repoDir = "."
	}

	diagDir := filepath.Join("build", "diagnostics")
	_ = os.MkdirAll(diagDir, 0755)

	cfg := tcommon.Config{
		AgentVersion:   agentVersion,
		StackVersion:   agentStackVersion,
		BuildDir:       agentBuildDir,
		GOVersion:      goVersion,
		RepoDir:        repoDir,
		DiagnosticsDir: diagDir,
		StateDir:       ".integration-cache",
		Platforms:      testPlatforms(),
		Packages:       testPackages(),
		Groups:         testGroups(),
		Matrix:         matrix,
		SingleTest:     singleTest,
		VerboseMode:    mg.Verbose(),
		Timestamp:      timestamp,
		TestFlags:      goTestFlags,
		ExtraEnv:       extraEnv,
		BinaryName:     binaryName,
	}

	r, err := runner.NewRunner(cfg, instanceProvisioner, stackProvisioner, batches...)
	if err != nil {
		return nil, fmt.Errorf("failed to create runner: %w", err)
	}
	return r, nil
}

func shouldBuildAgent() bool {
	build := os.Getenv("BUILD_AGENT")
	if build == "" {
		return false
	}
	ret, err := strconv.ParseBool(build)
	if err != nil {
		return false
	}
	return ret
}

func timestampEnabled() bool {
	timestamp := os.Getenv("TEST_INTEG_TIMESTAMP")
	if timestamp == "" {
		return false
	}
	b, _ := strconv.ParseBool(timestamp)
	return b
}

func testPlatforms() []string {
	platformsStr := os.Getenv("TEST_PLATFORMS")
	if platformsStr == "" {
		return nil
	}
	var platforms []string
	for _, p := range strings.Split(platformsStr, " ") {
		if p != "" {
			platforms = append(platforms, p)
		}
	}
	return platforms
}

func testPackages() []string {
	packagesStr, defined := os.LookupEnv("TEST_PACKAGES")
	if !defined {
		return nil
	}

	var packages []string
	for _, p := range strings.Split(packagesStr, ",") {
		if p == "tar.gz" {
			p = "targz"
		}
		packages = append(packages, p)
	}

	return packages
}

func testGroups() []string {
	groupsStr := os.Getenv("TEST_GROUPS")
	if groupsStr == "" {
		return nil
	}
	var groups []string
	for _, g := range strings.Split(groupsStr, " ") {
		if g != "" {
			groups = append(groups, g)
		}
	}
	return groups
}

// Pre-requisite: user must have the gcloud CLI installed
func authGCP(ctx context.Context) error {
	// We only need the service account token to exist.
	tokenPath, ok, err := getGCEServiceTokenPath()
	if err != nil {
		return err
	}
	if ok {
		// exists, so nothing to do
		return nil
	}

	// Use OS-appropriate command to find executables
	execFindCmd := "which"
	cliName := "gcloud"
	if runtime.GOOS == "windows" {
		execFindCmd = "where"
		cliName += ".exe"
	}

	// Check if gcloud CLI is installed
	cmd := exec.CommandContext(ctx, execFindCmd, cliName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s CLI is not installed: %w", cliName, err)
	}

	// Check if user is already authenticated
	var authList []struct {
		Account string `json:"account"`
	}
	for authSuccess := false; !authSuccess; {
		cmd = exec.CommandContext(ctx, cliName, "auth", "list", "--filter=status:ACTIVE", "--format=json")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("unable to list authenticated accounts: %w", err)
		}

		if err := json.Unmarshal(output, &authList); err != nil {
			return fmt.Errorf("unable to parse authenticated accounts: %w", err)
		}

		if len(authList) > 0 {
			// We have at least one authenticated, active account. All set!
			authSuccess = true
			continue
		}

		fmt.Fprintln(os.Stderr, "❌  GCP authentication unsuccessful. Retrying...")

		// Try to authenticate user
		cmd = exec.CommandContext(ctx, cliName, "auth", "login")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("unable to authenticate user: %w", cliName, err)
		}
	}

	// Parse env vars for
	// - expected email domain (default: elastic.co)
	// - expected GCP project (default: elastic-platform-ingest)
	expectedEmailDomain := os.Getenv("TEST_INTEG_AUTH_EMAIL_DOMAIN")
	if expectedEmailDomain == "" {
		expectedEmailDomain = "elastic.co"
	}
	expectedProject := os.Getenv("TEST_INTEG_AUTH_GCP_PROJECT")
	if expectedProject == "" {
		expectedProject = "elastic-platform-ingest"
	}

	// Check that authenticated account's email domain name
	email := authList[0].Account
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[1] != expectedEmailDomain {
		return fmt.Errorf("please authenticate with your @%s email address (currently authenticated with %s)", expectedEmailDomain, email)
	}

	// Check the authenticated account's project
	cmd = exec.CommandContext(ctx, cliName, "config", "get", "core/project")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("unable to get project: %w", err)
	}
	project := strings.TrimSpace(string(output))
	if project != expectedProject {
		// Attempt to select correct GCP project
		fmt.Printf("Attempting to switch GCP project from [%s] to [%s]...\n", project, expectedProject)
		cmd = exec.CommandContext(ctx, cliName, "config", "set", "core/project", expectedProject)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err = cmd.Run(); err != nil {
			return fmt.Errorf("unable to switch project from [%s] to [%s]: %w", project, expectedProject, err)
		}
		project = expectedProject
	}

	// Check that the service account exists for the user
	var svcList []struct {
		Email string `json:"email"`
	}
	serviceAcctName := fmt.Sprintf("%s-agent-testing", strings.Replace(parts[0], ".", "-", -1))
	iamAcctName := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", serviceAcctName, project)
	cmd = exec.CommandContext(ctx, cliName, "iam", "service-accounts", "list", "--format=json")
	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("unable to list service accounts: %w", err)
	}
	if err := json.Unmarshal(output, &svcList); err != nil {
		return fmt.Errorf("unable to parse service accounts: %w", err)
	}
	found := false
	for _, svc := range svcList {
		if svc.Email == iamAcctName {
			found = true
			break
		}
	}
	if !found {
		cmd = exec.CommandContext(ctx, cliName, "iam", "service-accounts", "create", serviceAcctName)
		if err = cmd.Run(); err != nil {
			return fmt.Errorf("unable to create service account %s: %w", serviceAcctName, err)
		}
	}

	// Check that the service account has the required roles
	cmd = exec.CommandContext(
		ctx, cliName, "projects", "get-iam-policy", project,
		"--flatten=bindings[].members",
		fmt.Sprintf("--filter=bindings.members:serviceAccount:%s", iamAcctName),
		"--format=value(bindings.role)")
	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("unable to get roles for service account %s: %w", serviceAcctName, err)
	}
	roles := strings.Split(string(output), ";")
	missingRoles := gceFindMissingRoles(roles, []string{"roles/compute.admin", "roles/iam.serviceAccountUser"})
	for _, role := range missingRoles {
		cmd = exec.CommandContext(ctx, cliName, "projects", "add-iam-policy-binding", project,
			fmt.Sprintf("--member=serviceAccount:%s", iamAcctName),
			fmt.Sprintf("--role=%s", role))
		if err = cmd.Run(); err != nil {
			return fmt.Errorf("failed to add role %s to service account %s: %w", role, serviceAcctName, err)
		}
	}

	// Create the key for the service account
	cmd = exec.CommandContext(ctx, cliName, "iam", "service-accounts", "keys", "create", tokenPath,
		fmt.Sprintf("--iam-account=%s", iamAcctName))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("failed to create key %s for service account %s: %w", tokenPath, serviceAcctName, err)
	}

	return nil
}

func gceFindMissingRoles(actual []string, expected []string) []string {
	var missing []string
	for _, e := range expected {
		if !slices.Contains(actual, e) {
			missing = append(missing, e)
		}
	}
	return missing
}

func getGCEServiceTokenPath() (string, bool, error) {
	serviceTokenPath := os.Getenv("TEST_INTEG_AUTH_GCP_SERVICE_TOKEN_FILE")
	if serviceTokenPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", false, fmt.Errorf("unable to determine user's home directory: %w", err)
		}
		serviceTokenPath = filepath.Join(homeDir, ".config", "gcloud", "agent-testing-service-token.json")
	}
	_, err := os.Stat(serviceTokenPath)
	if os.IsNotExist(err) {
		return serviceTokenPath, false, nil
	} else if err != nil {
		return serviceTokenPath, false, fmt.Errorf("unable to check for service account key file at %s: %w", serviceTokenPath, err)
	}
	return serviceTokenPath, true, nil
}

func authESS(ctx context.Context) error {
	essAPIKeyFile, err := ess.GetESSAPIKeyFilePath()
	if err != nil {
		return err
	}
	_, err = os.Stat(essAPIKeyFile)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(essAPIKeyFile), 0700); err != nil {
			return fmt.Errorf("unable to create ESS config directory: %w", err)
		}

		if err := os.WriteFile(essAPIKeyFile, nil, 0600); err != nil {
			return fmt.Errorf("unable to initialize ESS API key file: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("unable to check if ESS config directory exists: %w", err)
	}

	// Read API key from file
	data, err := os.ReadFile(essAPIKeyFile)
	if err != nil {
		return fmt.Errorf("unable to read ESS API key: %w", err)
	}

	essAPIKey := strings.TrimSpace(string(data))

	// Attempt to use API key to check if it's valid
	for authSuccess := false; !authSuccess; {
		client := ess.NewClient(ess.Config{ApiKey: essAPIKey})
		u, err := client.GetAccount(ctx, ess.GetAccountRequest{})
		if err != nil {
			return fmt.Errorf("unable to successfully connect to ESS API: %w", err)
		}

		if u.ID != "" {
			// We have a user. It indicates that the API key works. All set!
			authSuccess = true
			continue
		}

		fmt.Fprintln(os.Stderr, "❌  ESS authentication unsuccessful. Retrying...")

		prompt := fmt.Sprintf("Please provide a ESS API key for %s. To get your API key, "+
			"visit %s/account/keys:", client.BaseURL(), strings.TrimRight(client.BaseURL(), "/api/v1"))
		essAPIKey, err = stringPrompt(prompt)
		if err != nil {
			return fmt.Errorf("unable to read ESS API key from prompt: %w", err)
		}
	}

	// Write API key to file for future use
	if err := os.WriteFile(essAPIKeyFile, []byte(essAPIKey), 0600); err != nil {
		return fmt.Errorf("unable to persist ESS API key for future use: %w", err)
	}

	return nil
}

// stringPrompt asks for a string value using the label
func stringPrompt(prompt string) (string, error) {
	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(os.Stdout, prompt+" ")
		s, err := r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("unable to read answer: %w", err)
		}

		s = strings.TrimSpace(s)
		if s != "" {
			return s, nil
		}
	}
}

func writeFile(name string, data []byte, perm os.FileMode) error {
	err := os.WriteFile(name, data, perm)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", name, err)
	}
	return nil
}

func hasSnapshotEnv() bool {
	snapshot := os.Getenv(snapshotEnv)
	if snapshot == "" {
		return false
	}
	b, _ := strconv.ParseBool(snapshot)

	return b
}

func hasRunUntilFailure() bool {
	runUntil := os.Getenv("TEST_RUN_UNTIL_FAILURE")
	b, _ := strconv.ParseBool(runUntil)
	return b
}

func hasCleanOnExit() bool {
	clean := os.Getenv("TEST_INTEG_CLEAN_ON_EXIT")
	b, _ := strconv.ParseBool(clean)
	return b
}

func (Otel) Readme() error {
	fmt.Println(">> Building internal/pkg/otel/README.md")

	readmeTmpl := filepath.Join("internal", "pkg", "otel", "templates", "README.md.tmpl")
	readmeOut := filepath.Join("internal", "pkg", "otel", "README.md")

	// read README template
	tmpl, err := template.ParseFiles(readmeTmpl)
	if err != nil {
		return fmt.Errorf("failed to parse README template: %w", err)
	}

	data, err := getOtelDependencies()
	if err != nil {
		return fmt.Errorf("Failed to get OTel dependencies: %w", err)
	}

	// resolve template
	out, err := os.OpenFile(readmeOut, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", readmeOut, err)
	}
	defer out.Close()

	err = tmpl.Execute(out, data)
	if err != nil {
		return fmt.Errorf("failed to execute README template: %w", err)
	}

	// check that links are live
	mg.Deps(devtools.CheckLinksInFileAreLive(readmeOut))
	return nil
}

func getOtelDependencies() (*otelDependencies, error) {
	// read go.mod
	readFile, err := os.Open("go.mod")
	if err != nil {
		return nil, err
	}
	defer readFile.Close()

	scanner := bufio.NewScanner(readFile)

	scanner.Split(bufio.ScanLines)
	var receivers, extensions, exporters, processors, connectors []*otelDependency
	// process imports
	for scanner.Scan() {
		l := strings.TrimSpace(scanner.Text())
		dependency := newOtelDependency(l)
		if dependency == nil {
			continue
		}

		if dependency.ComponentType == "connector" {
			connectors = append(connectors, dependency)
		} else if dependency.ComponentType == "exporter" {
			exporters = append(exporters, dependency)
		} else if dependency.ComponentType == "extension" {
			extensions = append(extensions, dependency)
		} else if dependency.ComponentType == "processor" {
			processors = append(processors, dependency)
		} else if dependency.ComponentType == "receiver" {
			receivers = append(receivers, dependency)
		}
	}

	return &otelDependencies{
		Connectors: connectors,
		Exporters:  exporters,
		Extensions: extensions,
		Processors: processors,
		Receivers:  receivers,
	}, nil
}

type otelDependency struct {
	ComponentType string
	Name          string
	Version       string
	Link          string
}

func newOtelDependency(l string) *otelDependency {
	if !strings.Contains(l, "go.opentelemetry.io/") &&
		!strings.Contains(l, "github.com/open-telemetry/") &&
		!strings.Contains(l, "github.com/elastic/opentelemetry-collector-components/") {
		return nil
	}

	if strings.Contains(l, "// indirect") {
		return nil
	}

	chunks := strings.SplitN(l, " ", 2)
	if len(chunks) != 2 {
		return nil
	}
	dependencyURI := chunks[0]
	version := chunks[1]

	componentName := getOtelComponentName(dependencyURI)
	componentType := getOtelComponentType(dependencyURI)
	link := getOtelDependencyLink(dependencyURI, version)

	return &otelDependency{
		ComponentType: componentType,
		Name:          componentName,
		Version:       version,
		Link:          link,
	}
}

func getOtelComponentName(dependencyName string) string {
	parts := strings.Split(dependencyName, "/")
	return parts[len(parts)-1]
}

func getOtelComponentType(dependencyName string) string {
	if strings.Contains(dependencyName, "/connector/") {
		return "connector"
	} else if strings.Contains(dependencyName, "/exporter/") {
		return "exporter"
	} else if strings.Contains(dependencyName, "/extension/") {
		return "extension"
	} else if strings.Contains(dependencyName, "/processor/") {
		return "processor"
	} else if strings.Contains(dependencyName, "/receiver/") {
		return "receiver"
	}
	return ""
}

func getOtelDependencyLink(dependencyURI string, version string) string {
	dependencyRepository := getDependencyRepository(dependencyURI)
	dependencyPath := strings.TrimPrefix(dependencyURI, dependencyRepository+"/")
	repositoryURL := getOtelRepositoryURL(dependencyURI)
	return fmt.Sprintf("https://%s/blob/%s/%s/%s/README.md", repositoryURL, dependencyPath, version, dependencyPath)
}

func getDependencyRepository(dependencyURI string) string {
	dependencyURIChunks := strings.Split(dependencyURI, "/")
	if len(dependencyURIChunks) < 2 {
		return ""
	}
	var dependencyRepository string
	if dependencyURIChunks[0] == "go.opentelemetry.io" {
		dependencyRepository = dependencyURIChunks[0] + "/" + dependencyURIChunks[1]
	} else {
		dependencyRepository = dependencyURIChunks[0] + "/" + dependencyURIChunks[1] + "/" + dependencyURIChunks[2]
	}
	return dependencyRepository
}

func getOtelRepositoryURL(dependencyURI string) string {
	if strings.HasPrefix(dependencyURI, "go.opentelemetry.io/") {
		return "github.com/open-telemetry/opentelemetry-collector"
	} else if strings.HasPrefix(dependencyURI, "github.com/") {
		parts := strings.SplitN(dependencyURI, "/", 4)
		hostPart := parts[0]
		orgPart := parts[1]
		repoPart := parts[2]
		return fmt.Sprintf("%s/%s/%s", hostPart, orgPart, repoPart)
	}
	return ""
}

type otelDependencies struct {
	Connectors []*otelDependency
	Exporters  []*otelDependency
	Extensions []*otelDependency
	Processors []*otelDependency
	Receivers  []*otelDependency
}

type Helm mg.Namespace

func (Helm) RenderExamples() error {
	settings := cli.New() // Helm CLI settings
	actionConfig := &action.Configuration{}

	helmChart, err := loader.Load(helmChartPath)
	if err != nil {
		return fmt.Errorf("failed to load helm chart: %w", err)
	}

	err = actionConfig.Init(settings.RESTClientGetter(), "default", "",
		func(format string, v ...interface{}) {})
	if err != nil {
		return fmt.Errorf("failed to init helm action config: %w", err)
	}

	examplesPath := filepath.Join(helmChartPath, "examples")
	dirEntries, err := os.ReadDir(examplesPath)
	if err != nil {
		return fmt.Errorf("failed to read %s dir: %w", examplesPath, err)
	}

	for _, d := range dirEntries {
		if !d.IsDir() {
			continue
		}

		exampleFullPath := filepath.Join(examplesPath, d.Name())

		helmValues := make(map[string]any)
		helmValuesFiles, err := filepath.Glob(filepath.Join(exampleFullPath, "*-values.yaml"))
		if err != nil {
			return fmt.Errorf("failed to get helm values files: %w", err)
		}

		for _, helmValuesFile := range helmValuesFiles {
			data, err := loadYamlFile(helmValuesFile)
			if err != nil {
				return fmt.Errorf("failed to load helm values file: %w", err)
			}
			maps.Copy(helmValues, data)
		}

		installAction := action.NewInstall(actionConfig)
		installAction.Namespace = "default"
		installAction.ReleaseName = "example"
		installAction.CreateNamespace = true
		installAction.UseReleaseName = true
		installAction.CreateNamespace = false
		installAction.DryRun = true
		installAction.Replace = true
		installAction.KubeVersion = &chartutil.KubeVersion{Version: "1.27.0"}
		installAction.ClientOnly = true
		release, err := installAction.Run(helmChart, helmValues)
		if err != nil {
			return fmt.Errorf("failed to install helm chart: %w", err)
		}

		renderedFolder := filepath.Join(exampleFullPath, "rendered")
		err = os.Mkdir(renderedFolder, 0o755)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("failed to create rendered directory: %w", err)
		}

		renderedManifestPath := filepath.Join(renderedFolder, "manifest.yaml")

		err = os.WriteFile(renderedManifestPath, []byte(release.Manifest), 0o644)
		if err != nil {
			return fmt.Errorf("failed to write rendered manifest: %w", err)
		}
	}

	return nil
}

func (Helm) UpdateAgentVersion() error {
	valuesFile := filepath.Join(helmChartPath, "values.yaml")

	data, err := os.ReadFile(valuesFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	isTagged, err := devtools.TagContainsCommit()
	if err != nil {
		return fmt.Errorf("failed to check if tag contains commit: %w", err)
	}

	if !isTagged {
		isTagged = os.Getenv(snapshotEnv) != ""
	}

	agentVersion := getVersion()

	// Parse YAML into a Node structure because
	// it maintains comments
	var rootNode yaml.Node
	err = yaml.Unmarshal(data, &rootNode)
	if err != nil {
		return fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	if rootNode.Kind != yaml.DocumentNode {
		return fmt.Errorf("root node is not a document node")
	} else if len(rootNode.Content) == 0 {
		return fmt.Errorf("root node has no content")
	}

	if err := updateYamlNodes(rootNode.Content[0], agentVersion, "agent", "version"); err != nil {
		return fmt.Errorf("failed to update agent version: %w", err)
	}

	if !isTagged {
		if err := updateYamlNodes(rootNode.Content[0], fmt.Sprintf("%s-SNAPSHOT", agentVersion), "agent", "image", "tag"); err != nil {
			return fmt.Errorf("failed to update agent image tag: %w", err)
		}
	}

	// Truncate values file
	file, err := os.Create(valuesFile)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer file.Close()

	// Create a YAML encoder with 2-space indentation
	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)

	// Encode the updated YAML node back to the file
	err = encoder.Encode(&rootNode)
	if err != nil {
		return fmt.Errorf("failed to encode updated YAML: %w", err)
	}

	return nil
}

func (Helm) Lint() error {
	settings := cli.New() // Helm CLI settings
	actionConfig := &action.Configuration{}

	err := actionConfig.Init(settings.RESTClientGetter(), "default", "",
		func(format string, v ...interface{}) {})
	if err != nil {
		return fmt.Errorf("failed to init helm action config: %w", err)
	}

	lintAction := action.NewLint()
	lintResult := lintAction.Run([]string{helmChartPath}, nil)
	if len(lintResult.Errors) > 0 {
		return fmt.Errorf("failed to lint helm chart: %w", errors.Join(lintResult.Errors...))
	}
	return nil
}

func updateYamlNodes(rootNode *yaml.Node, value string, keys ...string) error {
	if len(keys) == 0 {
		return fmt.Errorf("no keys provided")
	}

	for i := 0; i < len(rootNode.Content)-1; i += 2 {
		agentKey := rootNode.Content[i]
		agentValue := rootNode.Content[i+1]

		if agentKey.Value == keys[0] {
			if len(keys) == 1 {
				agentValue.Value = value
				return nil
			}

			return updateYamlNodes(agentValue, value, keys[1:]...)
		}
	}

	return fmt.Errorf("key %s not found", keys[0])
}

func loadYamlFile(path string) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := yaml.NewDecoder(f)
	var data map[string]any
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}
