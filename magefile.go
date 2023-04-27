// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/otiai10/copy"
	"github.com/pkg/errors"

	"github.com/elastic/e2e-testing/pkg/downloads"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"

	// mage:import
	"github.com/elastic/elastic-agent/dev-tools/mage/target/common"

	"github.com/elastic/elastic-agent/internal/pkg/release"

	// mage:import
	_ "github.com/elastic/elastic-agent/dev-tools/mage/target/integtest/notests"
	// mage:import
	"github.com/elastic/elastic-agent/dev-tools/mage/target/test"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
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

func CheckNoChanges() error {
	fmt.Println(">> fmt - go run")
	err := sh.RunV("go", "mod", "tidy", "-v")
	if err != nil {
		return errors.Wrap(err, "failed running go mod tidy, please fix the issues reported")
	}
	fmt.Println(">> fmt - git diff")
	err = sh.RunV("git", "diff")
	if err != nil {
		return errors.Wrap(err, "failed running git diff, please fix the issues reported")
	}
	fmt.Println(">> fmt - git update-index")
	err = sh.RunV("git", "update-index", "--refresh")
	if err != nil {
		return errors.Wrap(err, "failed running git update-index --refresh, please fix the issues reported")
	}
	fmt.Println(">> fmt - git diff-index")
	err = sh.RunV("git", "diff-index", "--exit-code", "HEAD", " --")
	if err != nil {
		return errors.Wrap(err, "failed running go mod tidy, please fix the issues reported")
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
	p := filepath.Join(wd, "pkg", "component", "fake")
	for _, name := range []string{"component", "shipper"} {
		binary := name
		if runtime.GOOS == "windows" {
			binary += ".exe"
		}

		fakeDir := filepath.Join(p, name)
		outputName := filepath.Join(fakeDir, binary)
		err := RunGo("build", "-o", outputName, filepath.Join(fakeDir))
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
	mg.SerialDeps(Check.License, Check.GoLint)
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

func getPackageName(beat, version, pkg string) (string, string) {
	if _, ok := os.LookupEnv(snapshotEnv); ok {
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
	mg.SerialDeps(Config, BuildPGP, BuildFleetCfg)
}

// CrossBuild cross-builds the beat for all target platforms.
func CrossBuild() error {
	return devtools.CrossBuild()
}

// CrossBuildGoDaemon cross-builds the go-daemon binary using Docker.
func CrossBuildGoDaemon() error {
	return devtools.CrossBuildGoDaemon()
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
		version = release.Version()
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
	version, found := os.LookupEnv("BEAT_VERSION")
	if !found {
		version = release.Version()
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

	// build deps only when drop is not provided
	if !found || len(dropPath) == 0 {
		// prepare new drop
		dropPath = filepath.Join("build", "distributions", "elastic-agent-drop")
		dropPath, err := filepath.Abs(dropPath)
		if err != nil {
			panic(err)
		}

		archivePath = movePackagesToArchive(dropPath, requiredPackages)

		defer os.RemoveAll(dropPath)
		os.Setenv(agentDropPath, dropPath)

		// cleanup after build
		defer os.Unsetenv(agentDropPath)

		if devtools.ExternalBuild == true {
			externalBinaries := []string{
				"auditbeat", "filebeat", "heartbeat", "metricbeat", "osquerybeat", "packetbeat",
				// "cloudbeat", // TODO: add once working
				"cloud-defend",
				"elastic-agent-shipper",
				"apm-server",
				"endpoint-security",
				"fleet-server",
				"pf-elastic-collector",
				"pf-elastic-symbolizer",
				"pf-host-agent",
			}

			ctx := context.Background()
			for _, binary := range externalBinaries {
				for _, platform := range platforms {
					reqPackage := platformPackages[platform]
					targetPath := filepath.Join(archivePath, reqPackage)
					os.MkdirAll(targetPath, 0755)
					newVersion, packageName := getPackageName(binary, version, reqPackage)
					err := fetchBinaryFromArtifactsApi(ctx, packageName, binary, newVersion, targetPath)
					if err != nil {
						if strings.Contains(err.Error(), "object not found") {
							fmt.Printf("Downloading %s: unsupported on %s, skipping\n", binary, platform)
						} else {
							panic(fmt.Sprintf("fetchBinaryFromArtifactsApi failed for %s on %s: %v", binary, platform, err))
						}
					}
				}
			}
		} else {
			packedBeats := []string{"filebeat", "heartbeat", "metricbeat", "osquerybeat"}
			// build from local repo, will assume beats repo is located on the same root level
			for _, b := range packedBeats {
				pwd, err := filepath.Abs(filepath.Join("../beats/x-pack", b))
				if err != nil {
					panic(err)
				}

				if !requiredPackagesPresent(pwd, b, version, requiredPackages) {
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
						targetFile := filepath.Join(targetPath, filepath.Base(f))
						if err := sh.Copy(targetFile, f); err != nil {
							panic(err)
						}
					}
				}
			}
		}
	} else {
		archivePath = movePackagesToArchive(dropPath, requiredPackages)
	}
	defer os.RemoveAll(archivePath)

	// create flat dir
	flatPath := filepath.Join(dropPath, ".elastic-agent_flat")
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

		for _, m := range matches {
			stat, err := os.Stat(m)
			if os.IsNotExist(err) {
				continue
			} else if err != nil {
				panic(errors.Wrap(err, "failed stating file"))
			}

			if stat.IsDir() {
				continue
			}

			if err := devtools.Extract(m, versionedFlatPath); err != nil {
				panic(err)
			}
		}

		files, err := filepath.Glob(filepath.Join(versionedFlatPath, fmt.Sprintf("*%s*", version)))
		if err != nil {
			panic(err)
		}

		checksums := make(map[string]string)
		for _, f := range files {
			options := copy.Options{
				OnSymlink: func(_ string) copy.SymlinkAction {
					return copy.Shallow
				},
				Sync: true,
			}

			err = copy.Copy(f, versionedDropPath, options)
			if err != nil {
				panic(err)
			}

			// copy spec file for match
			specName := filepath.Base(f)
			idx := strings.Index(specName, "-"+version)
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
	packagingFn()

	mg.Deps(Update)
	mg.Deps(CrossBuild, CrossBuildGoDaemon)
	mg.SerialDeps(devtools.Package, TestPackages)
}

func copyComponentSpecs(componentName, versionedDropPath string) (string, error) {
	specFileName := componentName + specSuffix
	targetPath := filepath.Join(versionedDropPath, specFileName)

	if _, err := os.Stat(targetPath); err != nil {
		// spec not present copy from local
		sourceSpecFile := filepath.Join("specs", specFileName)
		err := devtools.Copy(sourceSpecFile, targetPath)
		if err != nil {
			return "", errors.Wrapf(err, "failed copying spec file %q to %q", sourceSpecFile, targetPath)
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
			fmt.Printf(">>> Computing hash for %q failed: file not present\n", componentFile)
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
				panic(errors.Wrap(err, "failed stating file"))
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
				panic(errors.Wrap(err, "failed renaming file"))
			}
		}
	}

	return archivePath
}

func fetchBinaryFromArtifactsApi(ctx context.Context, packageName, artifact, version, downloadPath string) error {
	// Only log fatal logs for logs produced using logrus. This is the global logger
	// used by github.com/elastic/e2e-testing/pkg/downloads which can only be configured globally like this or via
	// environment variables.
	//
	// Using FatalLevel avoids filling the build log with scary looking errors when we attempt to
	// download artifacts on unsupported platforms and choose to ignore the errors.
	logrus.SetLevel(logrus.FatalLevel)

	location, err := downloads.FetchBeatsBinary(
		ctx,
		packageName,
		artifact,
		version,
		3,
		false,
		downloadPath,
		true)
	if err != nil {
		return err
	}

	fmt.Println("downloaded binaries on", location)
	return err
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
		return errors.Wrap(err, "failed to prepare the IronBank context")
	}
	if err := saveIronbank(); err != nil {
		return errors.Wrap(err, "failed to save artifacts for IronBank")
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

	return errors.Wrap(devtools.CreateSHA512File(tarGzFile), "failed to create .sha512 file")
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
				return errors.Wrapf(err, "expanding template '%s' to '%s'", path, target)
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

func (Integration) Clean() {
	_ = os.RemoveAll(".agent-testing")
}

func (Integration) Local(ctx context.Context) error {
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
	return devtools.GoTest(ctx, params)
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
