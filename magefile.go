// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/elastic/e2e-testing/pkg/downloads"
	"github.com/elastic/elastic-agent/dev-tools/mage"
	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
	"github.com/elastic/elastic-agent/dev-tools/mage/manifest"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/ess"
	"github.com/elastic/elastic-agent/pkg/testing/multipass"
	"github.com/elastic/elastic-agent/pkg/testing/ogc"
	"github.com/elastic/elastic-agent/pkg/testing/runner"
	"github.com/elastic/elastic-agent/pkg/version"
	bversion "github.com/elastic/elastic-agent/version"

	// mage:import
	"github.com/elastic/elastic-agent/dev-tools/mage/target/common"
	// mage:import
	_ "github.com/elastic/elastic-agent/dev-tools/mage/target/integtest/notests"
	// mage:import
	"github.com/elastic/elastic-agent/dev-tools/mage/target/test"

	"github.com/hashicorp/go-multierror"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/otiai10/copy"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"
	"k8s.io/utils/strings/slices"
)

const (
	goLintRepo        = "golang.org/x/lint/golint"
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
	specSuffix        = ".spec.yml"
	checksumFilename  = "checksum.yml"
	commitLen         = 7

	cloudImageTmpl = "docker.elastic.co/observability-ci/elastic-agent:%s"
)

// Aliases for commands required by master makefile
var Aliases = map[string]interface{}{
	"build": Build.All,
	"demo":  Demo.Enroll,
}
var errNoManifest = errors.New("missing ManifestURL environment variable")
var errNoAgentDropPath = errors.New("missing AGENT_DROP_PATH environment variable")
var errAtLeastOnePlatform = errors.New("elastic-agent package is expected to build at least one platform package")

func init() {
	common.RegisterCheckDeps(Update, Check.All)
	test.RegisterDeps(UnitTest)
	devtools.BeatLicense = "Elastic License"
	devtools.BeatDescription = "Agent manages other beats based on configuration provided."

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
func (Dev) Package() {
	dev := os.Getenv(devEnv)
	defer os.Setenv(devEnv, dev)

	os.Setenv(devEnv, "true")

	if _, hasExternal := os.LookupEnv(externalArtifacts); !hasExternal {
		devtools.ExternalBuild = true
	}

	devtools.DevBuild = true
	Package()
}

// InstallGoLicenser install go-licenser to check license of the files.
func (Prepare) InstallGoLicenser() error {
	return GoGet(goLicenserRepo)
}

// InstallGoLint for the code.
func (Prepare) InstallGoLint() error {
	return GoGet(goLintRepo)
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
func (Build) Clean() {
	os.RemoveAll(buildDir)
}

// TestBinaries build the required binaries for the test suite.
func (Build) TestBinaries() error {
	wd, _ := os.Getwd()
	testBinaryPkgs := []string{
		filepath.Join(wd, "pkg", "component", "fake", "component"),
		filepath.Join(wd, "pkg", "component", "fake", "shipper"),
		filepath.Join(wd, "internal", "pkg", "agent", "install", "testblocking"),
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

// GoLint run the code through the linter.
func (Check) GoLint() error {
	mg.Deps(Prepare.InstallGoLint)
	packagesString, err := sh.Output("go", "list", "./...")
	if err != nil {
		return err
	}

	packages := strings.Split(packagesString, "\n")
	for _, pkg := range packages {
		if strings.Contains(pkg, "/vendor/") {
			continue
		}

		if e := sh.RunV("golint", "-set_exit_status", pkg); e != nil {
			err = multierror.Append(err, e)
		}
	}

	return err
}

// License makes sure that all the Golang files have the appropriate license header.
func (Check) License() error {
	mg.Deps(Prepare.InstallGoLicenser)
	// exclude copied files until we come up with a better option
	return combineErr(
		sh.RunV("go-licenser", "-d", "-license", "Elastic"),
	)
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
	return combineErr(
		sh.RunV("go-licenser", "-license", "Elastic"),
	)
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
		"build/golang-crossbuild/%s-darwin-amd64"}

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
func Package() {
	start := time.Now()
	defer func() { fmt.Println("package ran for", time.Since(start)) }()

	platforms := devtools.Platforms.Names()
	if len(platforms) == 0 {
		panic("elastic-agent package is expected to build at least one platform package")
	}

	packageAgent(platforms, devtools.UseElasticAgentPackaging)
}

// DownloadManifest downloads the provided manifest file into the predefined folder
func DownloadManifest() error {
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

	platformPackages := map[string]string{
		"darwin/amd64":  "darwin-x86_64.tar.gz",
		"darwin/arm64":  "darwin-aarch64.tar.gz",
		"linux/amd64":   "linux-x86_64.tar.gz",
		"linux/arm64":   "linux-arm64.tar.gz",
		"windows/amd64": "windows-x86_64.zip",
	}

	var requiredPackages []string
	for _, p := range platforms {
		requiredPackages = append(requiredPackages, platformPackages[p])
	}

	if e := manifest.DownloadComponentsFromManifest(devtools.ManifestURL, platforms, platformPackages, dropPath); e != nil {
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
	artifactRegexp, err := regexp.Compile(`([\w+-]+)-(([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+)?)-([\w]+)-([\w]+)-([\w]+)\.([\w]+)\.([\w.]+)`)
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
		targetName := fmt.Sprintf("%s-%s-%s-%s-image-%s-%s.%s", match[0][1], match[0][2], match[0][7], match[0][10], match[0][8], match[0][9], match[0][11])
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

func getPackageName(beat, version, pkg string) (string, string) {
	if hasSnapshotEnv() {
		version += "-SNAPSHOT"
	}
	return version, fmt.Sprintf("%s-%s-%s", beat, version, pkg)
}

func requiredPackagesPresent(basePath, beat, version string, requiredPackages []string) bool {
	for _, pkg := range requiredPackages {
		_, packageName := getPackageName(beat, version, pkg)
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

// GoGet fetch a remote dependencies.
func GoGet(link string) error {
	_, err := sh.Exec(map[string]string{"GO111MODULE": "off"}, os.Stdout, os.Stderr, "go", "get", link)
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

// CrossBuild cross-builds the beat for all target platforms.
func CrossBuild() error {
	return devtools.CrossBuild()
}

// CrossBuildGoDaemon cross-builds the go-daemon binary using Docker.
func CrossBuildGoDaemon() error {
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

// FakeShipperProto generates pkg/component/fake/common event protocol.
func FakeShipperProto() error {
	return sh.RunV(
		"protoc",
		"--go_out=.", "--go_opt=paths=source_relative",
		"--go-grpc_out=.", "--go-grpc_opt=paths=source_relative",
		"pkg/component/fake/common/event.proto")
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

func combineErr(errors ...error) error {
	var e error
	for _, err := range errors {
		if err == nil {
			continue
		}
		e = multierror.Append(e, err)
	}
	return e
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
func (Demo) Enroll() error {
	env := map[string]string{
		"FLEET_ENROLL": "1",
	}
	return runAgent(env)
}

// NoEnroll runs agent which does not enroll before running.
func (Demo) NoEnroll() error {
	env := map[string]string{
		"FLEET_ENROLL": "0",
	}
	return runAgent(env)
}

// Image builds a cloud image
func (Cloud) Image() {
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

	Package()
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

func runAgent(env map[string]string) error {
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
		// produce docker package
		packageAgent([]string{
			"linux/amd64",
		}, devtools.UseElasticAgentDemoPackaging)

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

func packageAgent(platforms []string, packagingFn func()) {
	fmt.Println("--- Package Elastic-Agent")
	var packageVersion string
	// if we have defined a manifest URL to package Agent from, we sould be using the same packageVersion of that manifest
	if devtools.PackagingFromManifest {
		if manifestResponse, err := manifest.DownloadManifest(devtools.ManifestURL); err != nil {
			log.Panicf("failed to download remote manifest file %s", err)
		} else {
			if parsedVersion, err := version.ParseVersion(manifestResponse.Version); err != nil {
				log.Panicf("the manifest version from manifest is not semver, got %s", manifestResponse.Version)
			} else {
				// When getting the packageVersion from snapshot we should also update the env of SNAPSHOT=true which is
				// something that we use as an implicit parameter to various functions
				if parsedVersion.IsSnapshot() {
					os.Setenv(snapshotEnv, "true")
					mage.Snapshot = true
				}
				os.Setenv("BEAT_VERSION", parsedVersion.CoreVersion())
			}
		}
	}
	if beatVersion, found := os.LookupEnv("BEAT_VERSION"); !found {
		packageVersion = bversion.GetDefaultVersion()
	} else {
		packageVersion = beatVersion
	}

	dropPath, found := os.LookupEnv(agentDropPath)
	var archivePath string

	platformPackages := map[string]string{
		"darwin/amd64":  "darwin-x86_64.tar.gz",
		"darwin/arm64":  "darwin-aarch64.tar.gz",
		"linux/amd64":   "linux-x86_64.tar.gz",
		"linux/arm64":   "linux-arm64.tar.gz",
		"windows/amd64": "windows-x86_64.zip",
	}

	requiredPackages := []string{}
	for _, p := range platforms {
		requiredPackages = append(requiredPackages, platformPackages[p])
	}
	if mg.Verbose() {
		log.Printf("--- Packaging packageVersion[%s], %+v \n", packageVersion, requiredPackages)
	}
	// build deps only when drop is not provided
	if !found || len(dropPath) == 0 {
		// prepare new drop
		dropPath = filepath.Join("build", "distributions", "elastic-agent-drop")
		dropPath, err := filepath.Abs(dropPath)
		if err != nil {
			panic(err)
		}

		if mg.Verbose() {
			log.Printf(">> Creating drop-in folder %+v \n", dropPath)
		}
		archivePath = movePackagesToArchive(dropPath, requiredPackages)

		defer os.RemoveAll(dropPath)
		os.Setenv(agentDropPath, dropPath)

		// cleanup after build
		defer os.Unsetenv(agentDropPath)

		if devtools.ExternalBuild == true {
			// Map of binaries to download to their project name in the unified-release manager.
			// The project names are used to generate the URLs when downloading binaries. For example:
			//
			// https://artifacts-snapshot.elastic.co/beats/latest/8.11.0-SNAPSHOT.json
			// https://artifacts-snapshot.elastic.co/cloudbeat/latest/8.11.0-SNAPSHOT.json
			// https://artifacts-snapshot.elastic.co/cloud-defend/latest/8.11.0-SNAPSHOT.json
			// https://artifacts-snapshot.elastic.co/apm-server/latest/8.11.0-SNAPSHOT.json
			// https://artifacts-snapshot.elastic.co/endpoint-dev/latest/8.11.0-SNAPSHOT.json
			// https://artifacts-snapshot.elastic.co/fleet-server/latest/8.11.0-SNAPSHOT.json
			// https://artifacts-snapshot.elastic.co/prodfiler/latest/8.11.0-SNAPSHOT.json
			externalBinaries := map[string]string{
				"auditbeat":             "beats",
				"filebeat":              "beats",
				"heartbeat":             "beats",
				"metricbeat":            "beats",
				"osquerybeat":           "beats",
				"packetbeat":            "beats",
				"cloudbeat":             "cloudbeat", // only supporting linux/amd64 or linux/arm64
				"cloud-defend":          "cloud-defend",
				"apm-server":            "apm-server", // not supported on darwin/aarch64
				"endpoint-security":     "endpoint-dev",
				"fleet-server":          "fleet-server",
				"pf-elastic-collector":  "prodfiler",
				"pf-elastic-symbolizer": "prodfiler",
				"pf-host-agent":         "prodfiler",
			}

			// Only log fatal logs for logs produced using logrus. This is the global logger
			// used by github.com/elastic/e2e-testing/pkg/downloads which can only be configured globally like this or via
			// environment variables.
			//
			// Using FatalLevel avoids filling the build log with scary looking errors when we attempt to
			// download artifacts on unsupported platforms and choose to ignore the errors.
			//
			// Change this to InfoLevel to see exactly what the downloader is doing.
			logrus.SetLevel(logrus.FatalLevel)

			errGroup, ctx := errgroup.WithContext(context.Background())
			completedDownloads := &atomic.Int32{}
			for binary, project := range externalBinaries {
				for _, platform := range platforms {
					reqPackage := platformPackages[platform]
					targetPath := filepath.Join(archivePath, reqPackage)
					os.MkdirAll(targetPath, 0755)
					newVersion, packageName := getPackageName(binary, packageVersion, reqPackage)
					errGroup.Go(downloadBinary(ctx, project, packageName, binary, platform, newVersion, targetPath, completedDownloads))
				}
			}

			err := errGroup.Wait()
			if err != nil {
				panic(err)
			}
			if completedDownloads.Load() == 0 {
				panic(fmt.Sprintf("No packages were successfully downloaded. You may be building against an invalid or unreleased version. version=%s. If this is an unreleased version, try SNAPSHOT=true or EXTERNAL=false", packageVersion))
			}
		} else {
			packedBeats := []string{"filebeat", "heartbeat", "metricbeat", "osquerybeat"}
			// build from local repo, will assume beats repo is located on the same root level
			for _, b := range packedBeats {
				pwd, err := filepath.Abs(filepath.Join("../beats/x-pack", b))
				if err != nil {
					panic(err)
				}

				packagesCopied := 0

				if !requiredPackagesPresent(pwd, b, packageVersion, requiredPackages) {
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
				for _, rp := range requiredPackages {
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
		archivePath = movePackagesToArchive(dropPath, requiredPackages)
	}
	defer os.RemoveAll(archivePath)

	// create flat dir
	flatPath := filepath.Join(dropPath, ".elastic-agent_flat")
	if mg.Verbose() {
		log.Printf("--- creating flat dir in .elastic-agent_flat")
	}
	os.MkdirAll(flatPath, 0755)
	defer os.RemoveAll(flatPath)

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
			log.Printf("--- Extracting into the flat dir")
		}
		for _, m := range matches {
			stat, err := os.Stat(m)
			if os.IsNotExist(err) {
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

		files, err := filepath.Glob(filepath.Join(versionedFlatPath, fmt.Sprintf("*%s*", packageVersion)))
		if err != nil {
			panic(err)
		}
		if mg.Verbose() {
			log.Printf("Validating checksums for %+v", files)
			log.Printf("--- Copy files into %s", versionedDropPath)
		}
		checksums := make(map[string]string)
		for _, f := range files {
			options := copy.Options{
				OnSymlink: func(_ string) copy.SymlinkAction {
					return copy.Shallow
				},
				Sync: true,
			}
			if mg.Verbose() {
				log.Printf("> prepare to copy %s ", f)
			}
			err = copy.Copy(f, versionedDropPath, options)
			if err != nil {
				panic(err)
			}

			// copy spec file for match
			specName := filepath.Base(f)
			idx := strings.Index(specName, "-"+packageVersion)
			if idx != -1 {
				specName = specName[:idx]
			}

			checksum, err := copyComponentSpecs(specName, versionedDropPath)
			if err != nil {
				panic(err)
			}

			checksums[specName+specSuffix] = checksum
		}

		if err := appendComponentChecksums(versionedDropPath, checksums); err != nil {
			panic(err)
		}
	}

	// package agent
	log.Println("--- Running packaging function")
	packagingFn()

	log.Println("--- Running post packaging ")
	mg.Deps(Update)
	mg.Deps(CrossBuild, CrossBuildGoDaemon)
	mg.SerialDeps(devtools.Package, TestPackages)
}

// Helper that wraps the fetchBinaryFromArtifactsApi in a way that is compatible with the errgroup.Go() function.
// Ensures the arguments are captured by value before starting the goroutine.
func downloadBinary(ctx context.Context, project string, packageName string, binary string, platform string, version string, targetPath string, compl *atomic.Int32) func() error {
	return func() error {
		_, err := downloads.FetchProjectBinary(ctx, project, packageName, binary, version, 3, false, targetPath, true)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				fmt.Printf("Could not download %s: %s\n", binary, err)
			} else {
				return fmt.Errorf("FetchProjectBinary failed for %s on %s: %v", binary, platform, err)
			}
		} else {
			compl.Add(1)
		}

		fmt.Printf("Done downloading %s\n", packageName)
		return nil
	}
}

func copyComponentSpecs(componentName, versionedDropPath string) (string, error) {
	specFileName := componentName + specSuffix
	targetPath := filepath.Join(versionedDropPath, specFileName)

	if _, err := os.Stat(targetPath); err != nil {
		fmt.Printf(">> File %s does not exist, reverting to local specfile\n", targetPath)
		// spec not present copy from local
		sourceSpecFile := filepath.Join("specs", specFileName)
		if mg.Verbose() {
			log.Printf("Copy spec from %s to %s", sourceSpecFile, targetPath)
		}
		err := devtools.Copy(sourceSpecFile, targetPath)
		if err != nil {
			return "", fmt.Errorf("failed copying spec file %q to %q: %w", sourceSpecFile, targetPath, err)
		}
	}

	// compute checksum
	return devtools.GetSHA512Hash(targetPath)
}

func appendComponentChecksums(versionedDropPath string, checksums map[string]string) error {
	// for each spec file checksum calculate binary checksum as well
	for file := range checksums {
		if !strings.HasSuffix(file, specSuffix) {
			continue
		}

		componentFile := strings.TrimSuffix(file, specSuffix)
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
func movePackagesToArchive(dropPath string, requiredPackages []string) string {
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
		for _, rp := range requiredPackages {
			if !strings.Contains(f, rp) {
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

			targetPath := filepath.Join(archivePath, rp, filepath.Base(f))
			targetDir := filepath.Dir(targetPath)
			if err := os.MkdirAll(targetDir, 0750); err != nil {
				fmt.Printf("warning: failed to create directory %s: %s", targetDir, err)
			}
			if err := os.Rename(f, targetPath); err != nil {
				panic(fmt.Errorf("failed renaming file: %w", err))
			}
		}
	}

	return archivePath
}

func selectedPackageTypes() string {
	if len(devtools.SelectedPackageTypes) == 0 {
		return ""
	}

	return "PACKAGES=targz,zip"
}

func copyAll(from, to string, suffixes ...[]string) error {
	return filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		targetFile := filepath.Join(to, info.Name())

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

	err := filepath.Walk(templatesDir, func(path string, info os.FileInfo, _ error) error {
		if !info.IsDir() {
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
			"-test.timeout", "2h", "-test.run", "^("+strings.Join(packageTests, "|")+")$")
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

func integRunner(ctx context.Context, matrix bool, singleTest string) error {
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

func createTestRunner(matrix bool, singleTest string, goTestFlags string, batches ...define.Batch) (*runner.Runner, error) {
	goVersion, err := mage.DefaultBeatBuildVariableSources.GetGoVersion()
	if err != nil {
		return nil, err
	}

	agentStackVersion := os.Getenv("AGENT_STACK_VERSION")
	agentVersion := os.Getenv("AGENT_VERSION")
	if agentVersion == "" {
		agentVersion, err = mage.DefaultBeatBuildVariableSources.GetBeatVersion()
		if err != nil {
			return nil, err
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

	// Possible to change the region for deployment, default is gcp-us-west2 which is
	// the CFT region.
	essRegion := os.Getenv("TEST_INTEG_AUTH_ESS_REGION")
	if essRegion == "" {
		essRegion = "gcp-us-west2"
	}

	instanceProvisionerMode := os.Getenv("INSTANCE_PROVISIONER")
	if instanceProvisionerMode == "" {
		instanceProvisionerMode = "ogc"
	}
	if instanceProvisionerMode != "ogc" && instanceProvisionerMode != "multipass" {
		return nil, fmt.Errorf("INSTANCE_PROVISIONER environment variable must be one of 'ogc' or 'multipass', not %s", instanceProvisionerMode)
	}
	fmt.Printf(">>>> Using %s instance provisioner\n", instanceProvisionerMode)
	stackProvisionerMode := os.Getenv("STACK_PROVISIONER")
	if stackProvisionerMode == "" {
		stackProvisionerMode = ess.ProvisionerStateful
	}
	if stackProvisionerMode != ess.ProvisionerStateful &&
		stackProvisionerMode != ess.ProvisionerServerless {
		return nil, fmt.Errorf("STACK_PROVISIONER environment variable must be one of %q or %q, not %s",
			ess.ProvisionerStateful,
			ess.ProvisionerServerless,
			stackProvisionerMode)
	}
	fmt.Printf(">>>> Using %s stack provisioner\n", stackProvisionerMode)

	timestamp := timestampEnabled()

	extraEnv := map[string]string{}
	if os.Getenv("AGENT_COLLECT_DIAG") != "" {
		extraEnv["AGENT_COLLECT_DIAG"] = os.Getenv("AGENT_COLLECT_DIAG")
	}
	if os.Getenv("AGENT_KEEP_INSTALLED") != "" {
		extraEnv["AGENT_KEEP_INSTALLED"] = os.Getenv("AGENT_KEEP_INSTALLED")
	}

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

	cfg := runner.Config{
		AgentVersion:   agentVersion,
		StackVersion:   agentStackVersion,
		BuildDir:       agentBuildDir,
		GOVersion:      goVersion,
		RepoDir:        repoDir,
		DiagnosticsDir: diagDir,
		StateDir:       ".integration-cache",
		Platforms:      testPlatforms(),
		Groups:         testGroups(),
		Matrix:         matrix,
		SingleTest:     singleTest,
		VerboseMode:    mg.Verbose(),
		Timestamp:      timestamp,
		TestFlags:      goTestFlags,
		ExtraEnv:       extraEnv,
		BinaryName:     binaryName,
	}
	ogcCfg := ogc.Config{
		ServiceTokenPath: serviceTokenPath,
		Datacenter:       datacenter,
	}
	email, err := ogcCfg.ClientEmail()
	if err != nil {
		return nil, err
	}

	var instanceProvisioner runner.InstanceProvisioner
	if instanceProvisionerMode == multipass.Name {
		instanceProvisioner = multipass.NewProvisioner()
	} else if instanceProvisionerMode == ogc.Name {
		instanceProvisioner, err = ogc.NewProvisioner(ogcCfg)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("unknown instance provisioner: %s", instanceProvisionerMode)
	}

	provisionCfg := ess.ProvisionerConfig{
		Identifier: fmt.Sprintf("at-%s", strings.Replace(strings.Split(email, "@")[0], ".", "-", -1)),
		APIKey:     essToken,
		Region:     essRegion,
	}
	var stackProvisioner runner.StackProvisioner
	if stackProvisionerMode == ess.ProvisionerStateful {
		stackProvisioner, err = ess.NewProvisioner(provisionCfg)
		if err != nil {
			return nil, err
		}

	} else if stackProvisionerMode == ess.ProvisionerServerless {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		stackProvisioner, err = ess.NewServerlessProvisioner(ctx, provisionCfg)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("unknown stack provisioner: %s", stackProvisionerMode)
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
	var found = false
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
		u, err := client.GetUser(ctx, ess.GetUserRequest{})
		if err != nil {
			return fmt.Errorf("unable to successfully connect to ESS API: %w", err)
		}

		if u.User.UserID != 0 {
			// We have a user. It indicates that the API key works. All set!
			authSuccess = true
			continue
		}

		fmt.Fprintln(os.Stderr, "❌  ESS authentication unsuccessful. Retrying...")

		prompt := fmt.Sprintf("Please provide a ESS API key for %s. To get your API key, "+
			"visit %s/deployment-features/keys:", client.BaseURL(), strings.TrimRight(client.BaseURL(), "/api/v1"))
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

	return "", nil
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

type dependency struct {
	Name    string
	Version string
}

type dependencies struct {
	Receivers  []dependency
	Exporters  []dependency
	Processors []dependency
	Extensions []dependency
}

func (d dependency) Clean(sep string) dependency {
	cleanFn := func(dep, sep string) string {
		chunks := strings.SplitN(dep, sep, 2)
		if len(chunks) == 2 {
			return chunks[1]
		}

		return dep
	}

	return dependency{
		Name:    cleanFn(d.Name, sep),
		Version: d.Version,
	}
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

	return tmpl.Execute(out, data)
}

func getOtelDependencies() (*dependencies, error) {
	// read go.mod
	readFile, err := os.Open("go.mod")
	if err != nil {
		return nil, err
	}
	defer readFile.Close()

	scanner := bufio.NewScanner(readFile)

	scanner.Split(bufio.ScanLines)
	var receivers, extensions, exporters, processors []dependency
	// process imports
	for scanner.Scan() {
		l := strings.TrimSpace(scanner.Text())
		// is otel
		if !strings.Contains(l, "go.opentelemetry.io/") &&
			!strings.Contains(l, "github.com/open-telemetry/") {
			continue
		}

		if strings.Contains(l, "// indirect") {
			continue
		}

		parseLine := func(line string) (dependency, error) {
			chunks := strings.SplitN(line, " ", 2)
			if len(chunks) != 2 {
				return dependency{}, fmt.Errorf("incorrect format for line %q", line)
			}
			return dependency{
				Name:    chunks[0],
				Version: chunks[1],
			}, nil
		}

		d, err := parseLine(l)
		if err != nil {
			return nil, err
		}

		if strings.Contains(l, "/receiver/") {
			receivers = append(receivers, d.Clean("/receiver/"))
		} else if strings.Contains(l, "/processor/") {
			processors = append(processors, d.Clean("/processor/"))
		} else if strings.Contains(l, "/exporter/") {
			exporters = append(exporters, d.Clean("/exporter/"))
		} else if strings.Contains(l, "/extension/") {
			extensions = append(extensions, d.Clean("/extension/"))
		}
	}

	return &dependencies{
		Receivers:  receivers,
		Exporters:  exporters,
		Processors: processors,
		Extensions: extensions,
	}, nil
}
