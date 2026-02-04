// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build mage

package main

import (
	"bufio"
	"bytes"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elastic/elastic-agent/dev-tools/mage/otel"

	"github.com/jedib0t/go-pretty/v6/table"
	filecopy "github.com/otiai10/copy"

	metricbeat "github.com/elastic/beats/v7/metricbeat/scripts/mage"
	packetbeat "github.com/elastic/beats/v7/packetbeat/scripts/mage"
	osquerybeat "github.com/elastic/beats/v7/x-pack/osquerybeat/scripts/mage"
	xpacketbeat "github.com/elastic/beats/v7/x-pack/packetbeat/scripts/mage"

	"github.com/elastic/elastic-agent/dev-tools/devmachine"
	"github.com/elastic/elastic-agent/dev-tools/mage"
	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
	"github.com/elastic/elastic-agent/dev-tools/mage/downloads"
	"github.com/elastic/elastic-agent/dev-tools/mage/manifest"
	"github.com/elastic/elastic-agent/dev-tools/mage/pkgcommon"
	"github.com/elastic/elastic-agent/dev-tools/packaging"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/pkg/testing/buildkite"
	tcommon "github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/ess"
	"github.com/elastic/elastic-agent/pkg/testing/kubernetes"
	"github.com/elastic/elastic-agent/pkg/testing/kubernetes/kind"
	"github.com/elastic/elastic-agent/pkg/testing/multipass"
	"github.com/elastic/elastic-agent/pkg/testing/ogc"
	"github.com/elastic/elastic-agent/pkg/testing/runner"
	"github.com/elastic/elastic-agent/pkg/testing/tools/git"
	pv "github.com/elastic/elastic-agent/pkg/testing/tools/product_versions"
	"github.com/elastic/elastic-agent/pkg/testing/tools/snapshots"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/integration/k8s"
	"github.com/elastic/elastic-agent/testing/upgradetest"
	bversion "github.com/elastic/elastic-agent/version"

	// mage:import
	"github.com/elastic/elastic-agent/dev-tools/mage/target/common"
	// mage:import
	_ "github.com/elastic/elastic-agent/dev-tools/mage/target/integtest/notests"
	// mage:import update
	_ "github.com/elastic/elastic-agent/dev-tools/mage/target/update"
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
	"helm.sh/helm/v3/pkg/downloader"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/repo"
)

const (
	goLicenserRepo    = "github.com/elastic/go-licenser"
	buildDir          = "build"
	metaDir           = "_meta"
	snapshotEnv       = "SNAPSHOT"
	devEnv            = "DEV"
	fipsEnv           = "FIPS"
	externalArtifacts = "EXTERNAL"
	platformsEnv      = "PLATFORMS"
	packagesEnv       = "PACKAGES"
	dockerVariants    = "DOCKER_VARIANTS"
	configFile        = "elastic-agent.yml"
	agentDropPath     = "AGENT_DROP_PATH"
	checksumFilename  = "checksum.yml"
	commitLen         = 7

	cloudImageTmpl = "docker.elastic.co/observability-ci/elastic-agent:%s"

	baseURLForSnapshotDRA = "https://snapshots.elastic.co/"
	agentCoreProjectName  = "elastic-agent-core"

	helmChartPath      = "./deploy/helm/elastic-agent"
	helmOtelChartPath  = "./deploy/helm/edot-collector/kube-stack"
	helmMOtelChartPath = "./deploy/helm/edot-collector/kube-stack/managed_otlp"
	sha512FileExt      = ".sha512"
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
	common.RegisterCheckDeps(Update, Check.All, Otel.Readme)
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

// Devmachine namespace contains tasks related to remote development machines.
type Devmachine mg.Namespace

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

func (Dev) RegenerateMocks() error {
	err := sh.Run("mockery")
	if err != nil {
		return fmt.Errorf("generating mocks: %w", err)
	}

	mg.Deps(devtools.Format)
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

// windowsArchiveRootBinaryForGoArch compiles a binary to be placed at the root of the windows elastic-agent archive. This binary
// is a thin proxy to the actual elastic-agent binary that resides in the data/elastic-agent-{commit-short-sha}
// directory of the archive.
func (Build) windowsArchiveRootBinaryForGoArch(goarch string) error {
	fmt.Printf("--- Compiling root binary for %s windows archive\n", goarch)
	hashShort, err := devtools.CommitHashShort()
	if err != nil {
		return fmt.Errorf("error getting commit hash: %w", err)
	}

	outputName := "elastic-agent-archive-root"
	if runtime.GOOS != "windows" {
		// add the .exe extension on non-windows platforms
		outputName += ".exe"
	}

	args := devtools.BuildArgs{
		Name:        outputName,
		OutputDir:   filepath.Join(buildDir, fmt.Sprintf("windows-%s-archive-root-binary", goarch)),
		InputFiles:  []string{"wrapper/windows/archive-proxy/main.go"},
		CGO:         false,
		WinMetadata: true,
		ExtraFlags: []string{
			"-buildmode", "pie", // windows versions inside the support matrix do support position independent code
			"-trimpath", // Remove all file system paths from the compiled executable, to improve build reproducibility
		},
		Vars: map[string]string{
			"main.CommitSHA": hashShort,
		},
		Env: map[string]string{
			"GOOS":   "windows",
			"GOARCH": goarch,
		},
		LDFlags: []string{
			"-s", // Strip all debug symbols from binary (does not affect Go stack traces).
		},
	}

	if devtools.FIPSBuild {
		// there is no actual FIPS relevance for this particular binary
		// but better safe than sorry
		args.ExtraFlags = append(args.ExtraFlags, "-tags=requirefips,ms_tls13kdf")
		args.Env["MS_GOTOOLCHAIN_TELEMETRY_ENABLED"] = "0"
		args.CGO = true
	}

	return devtools.Build(args)
}

// WindowsArchiveRootBinary compiles a binary to be placed at the root of the windows elastic-agent archive. This binary
// is a thin proxy to the actual elastic-agent binary that resides in the data/elastic-agent-{commit-short-sha}
// directory of the archive.
func (Build) WindowsArchiveRootBinary() {
	for _, p := range devtools.Platforms {
		if p.GOOS() == "windows" {
			mg.Deps(mg.F(Build.windowsArchiveRootBinaryForGoArch, p.GOARCH()))
		}
	}
}

// GolangCrossBuild build the Beat binary inside of the golang-builder.
// Do not use directly, use crossBuild instead.
func GolangCrossBuild() error {
	params := devtools.DefaultGolangCrossBuildArgs()
	params.OutputDir = "build/golang-crossbuild"
	params.Package = "github.com/elastic/elastic-agent"
	injectBuildVars(params.Vars)

	if err := devtools.GolangCrossBuild(params); err != nil {
		return err
	}

	return nil
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

// TestBinaries build the required binaries for the test suite.
func (Build) TestBinaries() error {
	testBinaryPkgs, err := getTestBinariesPath()
	if err != nil {
		return fmt.Errorf("cannot build test binaries: %w", err)
	}
	return buildTestBinaries(testBinaryPkgs)
}

// TestFakeComponent build just the test fake component.
func (Build) TestFakeComponent() error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("could not get working directory: %w", err)
	}
	testBinaryPkgs := []string{
		filepath.Join(wd, "pkg", "component", "fake", "component"),
	}
	return buildTestBinaries(testBinaryPkgs)
}

func getTestBinariesPath() ([]string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("could not get working directory: %w", err)
	}

	testBinaryPkgs := []string{
		filepath.Join(wd, "pkg", "component", "fake", "component"),
		filepath.Join(wd, "internal", "pkg", "agent", "install", "testblocking"),
		filepath.Join(wd, "pkg", "core", "process", "testsignal"),
		filepath.Join(wd, "internal", "pkg", "agent", "application", "filelock", "testlocker"),
		filepath.Join(wd, "internal", "edot", "testing"),
	}
	return testBinaryPkgs, nil
}

func buildTestBinaries(testBinaryPkgs []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("could not get working directory: %w", err)
	}

	buildArgs := []string{"build", "-v"}
	if runtime.GOOS == "darwin" {
		osMajorVer, err := getMacOSMajorVersion()
		if err != nil {
			return fmt.Errorf("cannot determine darwin OS major version: %w", err)
		}

		if osMajorVer > 13 {
			// Workaround for https://github.com/golang/go/issues/67854 until it
			// is resolved.
			buildArgs = append(buildArgs, "-ldflags", "-extldflags='-ld_classic'")
		}
	}

	edotRoot := filepath.Join(wd, "internal", "edot")
	for _, pkg := range testBinaryPkgs {
		binary := filepath.Base(pkg)
		if runtime.GOOS == "windows" {
			binary += ".exe"
		}

		outputName := filepath.Join(pkg, binary)
		finalArgs := make([]string, 0, len(buildArgs)+4)

		// test binaries under internal/edot must be built using internal/edot's go.mod
		if strings.HasPrefix(pkg, edotRoot) {
			// use -C to run go from internal/edot directory so it uses that go.mod
			finalArgs = append(finalArgs, "-C", "internal/edot")
			finalArgs = append(finalArgs, buildArgs...)
			finalArgs = append(finalArgs, "-o", outputName)
			// calculate the relative path from internal/edot to the package
			relPath, err := filepath.Rel(edotRoot, pkg)
			if err != nil {
				return fmt.Errorf("could not determine relative path for %s: %w", pkg, err)
			}
			finalArgs = append(finalArgs, "./"+relPath)
		} else {
			finalArgs = append(finalArgs, buildArgs...)
			finalArgs = append(finalArgs, "-o", outputName, pkg)
		}

		if err = RunGo(finalArgs...); err != nil {
			return err
		}
		if err = os.Chmod(outputName, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// All run all the code and docs checks.
func (Check) All() {
	mg.SerialDeps(Check.License, Integration.Check, Check.DocsFiles)
}

// License makes sure that all the Golang files have the appropriate license header.
func (Check) License() error {
	mg.Deps(Prepare.InstallGoLicenser)
	// exclude copied files until we come up with a better option
	return sh.RunV("go-licenser", "-d", "-license", "Elasticv2", "-exclude", "beats")
}

// DocsFiles validates that files required by the docs generation script exist.
func (Check) DocsFiles() error {
	fmt.Println("Validating files required by docs/scripts/update-docs/update-components-docs.py")

	requiredFiles := []string{
		"go.mod",
		"internal/edot/components.yml",
		"internal/edot/samples/linux/gateway.yml",
	}

	missing := false
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			fmt.Printf("❌ Missing: %s\n", file)
			missing = true
		} else {
			fmt.Printf("✅ Found: %s\n", file)
		}
	}

	if missing {
		fmt.Println()
		return fmt.Errorf("one or more files required by the docs generation script are missing.\n" +
			"If these files were intentionally moved, please update:\n" +
			"  - docs/scripts/update-docs/update-components-docs.py\n" +
			"  - magefile.go (Check.DocsFiles function)\n" +
			"  - .github/workflows/validate-docs-structure.yml")
	}

	fmt.Println()
	fmt.Println("✅ All required files are present.")
	return nil
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
		return fmt.Errorf("uncommitted changes")
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

// FIPSOnlyUnit runs all the unit tests with GODEBUG=fips140=only.
func (Test) FIPSOnlyUnit(ctx context.Context) error {
	mg.Deps(Prepare.Env, Build.TestBinaries)
	params := devtools.DefaultGoTestUnitArgs()
	params.Env["GODEBUG"] = "fips140=only"
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
	return sh.RunV("go-licenser", "-license", "Elastic", "-exclude", "beats")
}

// Package packages the Beat for distribution.
// Use SNAPSHOT=true to build snapshots.
// Use PLATFORMS to control the target platforms.
// Use VERSION_QUALIFIER to control the version qualifier.
func Package(ctx context.Context) error {
	start := time.Now()
	defer func() { fmt.Println("package ran for", time.Since(start)) }()

	if len(devtools.Platforms) == 0 {
		panic("elastic-agent package is expected to build at least one platform package")
	}

	// needs elastic-agent-core built first
	mg.Deps(PackageAgentCore)

	// switch to the main package target
	mage.UseElasticAgentPackaging()

	var err error
	if devtools.PackagingFromManifest {
		// manifest is not passed into packageAgent below because we want packageAgent to go through the
		// flow using the elastic-agent-core that was built above. if it was passed in, it would download
		// elastic-agent-core from the manifest and it would not be the code from this repository in the package
		_, _, err = downloadManifestAndSetVersion(ctx, devtools.ManifestURL)
		if err != nil {
			return fmt.Errorf("failed downloading manifest: %w", err)
		}
		// don't download the elastic-agent-core components; built above
		if err := downloadManifest(ctx, packaging.WithoutProjectName(agentCoreProjectName)); err != nil {
			return fmt.Errorf("failed downloading manifest components: %w", err)
		}
	}
	return packageAgent(ctx, "", nil)
}

// DownloadManifest downloads the provided manifest file into the predefined folder and downloads all components in the manifest.
func DownloadManifest(ctx context.Context) error {
	// Enforce that we use the correct elastic-agent packaging, to correctly load component dependencies
	// Use mg.Deps() to ensure that the function will be called only once per mage invocation.
	// devtools.Use*Packaging functions are not idempotent as they append in devtools.Packages
	mg.Deps(devtools.UseElasticAgentPackaging)
	return downloadManifest(ctx)
}

func downloadManifest(ctx context.Context, filters ...packaging.ComponentFilter) error {
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

	dependencies, err := ExtractComponentsFromSelectedPkgSpecs(devtools.Packages)
	if err != nil {
		return fmt.Errorf("failed extracting dependencies: %w", err)
	}

	// Only include components that support at least one of the selected package types
	filters = append(filters, supportsSelectedPackageTypesFilter(platforms, devtools.SelectedPackageTypes))
	dependencies = packaging.FilterComponents(dependencies, filters...)

	if e := manifest.DownloadComponents(ctx, dependencies, devtools.ManifestURL, platforms, dropPath); e != nil {
		return fmt.Errorf("failed to download the manifest file, %w", e)
	}
	log.Printf(">> Completed downloading packages from manifest into drop-in %s", dropPath)

	return nil
}

func ExtractComponentsFromSelectedPkgSpecs(pkgSpecs []devtools.OSPackageArgs) ([]packaging.BinarySpec, error) {
	// Extract the dependencies from the selected packages
	mappedDependencies := map[string]packaging.BinarySpec{}
	for _, pkg := range pkgSpecs {
		if isSelected(pkg) {
			if mg.Verbose() {
				log.Printf("package %s is selected, collecting dependencies", pkg.Spec.Name)
			}

			for _, component := range pkg.Spec.Components {
				if existingComp, ok := mappedDependencies[component.PackageName]; ok {
					// sanity check: verify that for the same packageName we have the same component spec
					if !existingComp.Equal(component) {
						return nil, fmt.Errorf("found component %+v and %+v sharing the same package name %q but they are not equal",
							existingComp, component, component.PackageName)
					}
				} else {
					mappedDependencies[component.PackageName] = component
					if mg.Verbose() {
						log.Printf("Added component %s to the list of component to download from manifest", component.PackageName)
					}
				}
			}
		}
	}

	// collect the dependencies into a slice
	dependencies := make([]packaging.BinarySpec, 0, len(mappedDependencies))
	for _, pkg := range mappedDependencies {
		dependencies = append(dependencies, pkg)
	}

	return dependencies, nil
}

func isSelected(pkg devtools.OSPackageArgs) bool {
	// Checks if this package is compatible with the FIPS settings
	if pkg.Spec.FIPS != devtools.FIPSBuild {
		log.Printf("Skipping %s/%s package type because FIPS flag doesn't match [pkg=%v, build=%v]", pkg.Spec.Name, pkg.OS, pkg.Spec.FIPS, devtools.FIPSBuild)
		return false
	}

	platforms := devtools.Platforms
	for _, platform := range platforms {
		if !isPackageSelectedForPlatform(pkg, platform) {
			continue
		}

		pkgTypesSelected := 0
		for _, pkgType := range pkg.Types {
			if !devtools.IsPackageTypeSelected(pkgType) {
				log.Printf("Skipping %s package type because it is not selected", pkgType)
				continue
			}

			if pkgType == devtools.Docker && !devtools.IsDockerVariantSelected(pkg.Spec.DockerVariant) {
				log.Printf("Skipping %s docker variant type because it is not selected", pkg.Spec.DockerVariant)
				continue
			}
			pkgTypesSelected++
		}
		// if we found at least one package type for one platform the package spec is selected
		return pkgTypesSelected > 0
	}
	return true
}

func isPackageSelectedForPlatform(pkg devtools.OSPackageArgs, platform devtools.BuildPlatform) bool {
	if pkg.OS == platform.GOOS() && (pkg.Arch == "" || pkg.Arch == platform.Arch()) {
		return true
	}

	return false
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
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create directory: %v, error: %+v", dir, err)
		}
		return nil
	}
}

// Update is an alias for executing control protocol, configs, and specs.
func Update() {
	mg.Deps(Config, BuildPGP, BuildFleetCfg)
}

func EnsureCrossBuildOutputDir() error {
	repositoryRoot, err := mage.ElasticBeatsDir()
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

// PackageAgentCore cross-builds and packages distribution artifacts containing
// only elastic-agent binaries with no extra files or dependencies.
func PackageAgentCore() error {
	start := time.Now()
	defer func() { fmt.Println("packageAgentCore ran for", time.Since(start)) }()

	forcedTar := false
	if devtools.IsPackageTypeSelected(devtools.Docker) && !devtools.IsPackageTypeSelected(devtools.TarGz) {
		// targz is required in the core package for docker images
		forcedTar = true
		devtools.SelectedPackageTypes = append(devtools.SelectedPackageTypes, devtools.TarGz)
	}

	fmt.Println("--- Build elastic-agent-core")
	mg.SerialDeps(Update, Otel.Prepare, Otel.CrossBuild, CrossBuild, Build.WindowsArchiveRootBinary)

	fmt.Println("--- Package elastic-agent-core")
	devtools.UseElasticAgentCorePackaging()

	// ran directly as we don't want mage to cache that it already called devtools.Package
	err := devtools.Package()
	if err != nil {
		return err
	}

	// remove targz, so its not built in a following step (if there is one)
	if forcedTar {
		devtools.SelectedPackageTypes = slices.DeleteFunc(devtools.SelectedPackageTypes, func(pt devtools.PackageType) bool { return pt == devtools.TarGz })
	}
	return nil
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

	if err := sh.RunV(
		"protoc",
		"--go_out=pkg/control/v1/proto", "--go_opt=paths=source_relative",
		"--go-grpc_out=pkg/control/v1/proto", "--go-grpc_opt=paths=source_relative",
		"control_v1.proto"); err != nil {
		return err
	}

	mg.Deps(devtools.AddLicenseHeaders, devtools.GoImports)
	return nil
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
	return RunGo("run", goF, "--in", in, "--output", out)
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

	variant := os.Getenv(dockerVariants)
	defer os.Setenv(dockerVariants, variant)

	fips := os.Getenv(fipsEnv)
	defer os.Setenv(fipsEnv, fips)

	os.Setenv(platformsEnv, "linux/amd64")
	os.Setenv(packagesEnv, "docker")
	os.Setenv(devEnv, "true")
	os.Setenv(dockerVariants, "cloud")

	if s, err := strconv.ParseBool(snapshot); err == nil && !s {
		// only disable SNAPSHOT build when explicitly defined
		os.Setenv(snapshotEnv, "false")
		devtools.Snapshot = false
	} else {
		os.Setenv(snapshotEnv, "true")
		devtools.Snapshot = true
	}

	fipsVal, err := strconv.ParseBool(fips)
	if err != nil {
		fipsVal = false
	}
	os.Setenv(fipsEnv, strconv.FormatBool(fipsVal))
	devtools.FIPSBuild = fipsVal

	devtools.DevBuild = true
	devtools.Platforms = devtools.Platforms.Filter("linux/amd64")
	devtools.SelectedPackageTypes = []devtools.PackageType{devtools.Docker}
	devtools.SelectedDockerVariants = []devtools.DockerVariant{devtools.Cloud}

	if _, hasExternal := os.LookupEnv(externalArtifacts); !hasExternal {
		devtools.ExternalBuild = true
	}

	Package(ctx)
}

// Load loads an artifact as a docker image.
// Looks in build/distributions for an elastic-agent-cloud*.docker.tar.gz artifact and imports it as docker.elastic.co/beats-ci/elastic-agent-cloud:$VERSION
// DOCKER_IMPORT_SOURCE - override source for import
func (Cloud) Load() error {
	agentVersion, err := mage.AgentPackageVersion()
	if err != nil {
		return fmt.Errorf("failed to get agent package version: %w", err)
	}

	// Need to get the FIPS env var flag to see if we are using the normal source cloud image name, or the FIPS variant
	fips := os.Getenv(fipsEnv)
	fipsVal, err := strconv.ParseBool(fips)
	if err != nil {
		fipsVal = false
	}

	devtools.FIPSBuild = fipsVal

	source := devtools.DistributionsDir + "/elastic-agent-cloud-" + agentVersion + "-SNAPSHOT-linux-" + runtime.GOARCH + ".docker.tar.gz"
	if fipsVal {
		source = devtools.DistributionsDir + "/elastic-agent-cloud-fips-" + agentVersion + "-SNAPSHOT-linux-" + runtime.GOARCH + ".docker.tar.gz"
	}
	if envSource, ok := os.LookupEnv("DOCKER_IMPORT_SOURCE"); ok && envSource != "" {
		source = envSource
	}

	return sh.RunV("docker", "image", "load", "-i", source)
}

// Push builds a cloud image tags it correctly and pushes to remote image repo.
// Previous login to elastic registry is required!
func (Cloud) Push() error {
	agentVersion, err := mage.AgentPackageVersion()
	if err != nil {
		return fmt.Errorf("failed to get agent package version: %w", err)
	}

	// Need to get the FIPS env var flag to see if we are using the normal source cloud image name, or the FIPS variant
	fips := os.Getenv(fipsEnv)
	defer os.Setenv(fipsEnv, fips)
	fipsVal, err := strconv.ParseBool(fips)
	if err != nil {
		fipsVal = false
	}
	if err := os.Setenv(fipsEnv, strconv.FormatBool(fipsVal)); err != nil {
		return fmt.Errorf("failed to set fips env var: %w", err)
	}
	devtools.FIPSBuild = fipsVal

	sourceCloudImageName := fmt.Sprintf("docker.elastic.co/beats-ci/elastic-agent-cloud:%s-SNAPSHOT", agentVersion)
	if fipsVal {
		sourceCloudImageName = fmt.Sprintf("docker.elastic.co/beats-ci/elastic-agent-cloud-fips:%s-SNAPSHOT", agentVersion)
	}
	var targetTag string
	if envTag, isPresent := os.LookupEnv("CUSTOM_IMAGE_TAG"); isPresent && len(envTag) > 0 {
		targetTag = envTag
	} else {
		targetTag = fmt.Sprintf("%s-%s-%d", agentVersion, dockerCommitHash(), time.Now().Unix())
	}
	var targetCloudImageName string
	if customImage, isPresent := os.LookupEnv("CI_ELASTIC_AGENT_DOCKER_IMAGE"); isPresent && len(customImage) > 0 {
		targetCloudImageName = fmt.Sprintf("%s:%s", customImage, targetTag)
	} else {
		targetCloudImageName = fmt.Sprintf(cloudImageTmpl, targetTag)
	}

	fmt.Printf(">> Setting a docker image tag to %s\n", targetCloudImageName)
	err = sh.RunV("docker", "tag", sourceCloudImageName, targetCloudImageName)
	if err != nil {
		return fmt.Errorf("failed setting a docker image tag: %w", err)
	}
	fmt.Println(">> Docker image tag updated successfully")

	fmt.Println(">> Pushing a docker image to remote registry")
	err = sh.RunV("docker", "image", "push", targetCloudImageName)
	if err != nil {
		return fmt.Errorf("failed pushing docker image: %w", err)
	}
	fmt.Printf(">> Docker image pushed to remote registry successfully: %s\n", targetCloudImageName)

	return nil
}

// Create a new devmachine that will be auto-deleted in 6 hours.
// Example: MACHINE_IMAGE="family/platform-ingest-elastic-agent-ubuntu-2204" ZONE="us-central1-a" mage devmachine:create "pavel-dev-machine"
// ZONE defaults to 'us-central1-a', MACHINE_IMAGE defaults to 'family/platform-ingest-elastic-agent-ubuntu-2204'
func (Devmachine) Create(instanceName string) error {
	if instanceName == "" {
		return errors.New(
			`instanceName is required.
	Example:
	mage devmachine:create "pavel-dev-machine"  `)
	}
	return devmachine.Run(instanceName)
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
		// produce docker package
		mage.UseElasticAgentPackaging()
		err = packageAgent(ctx, "", nil)
		if err != nil {
			return fmt.Errorf("failed to package elastic-agent: %w", err)
		}

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

func packageAgent(ctx context.Context, dependenciesVersion string, manifestResponse *manifest.Build) error {
	fmt.Println("--- Package elastic-agent")

	if dependenciesVersion == "" {
		if beatVersion, found := os.LookupEnv("BEAT_VERSION"); !found {
			dependenciesVersion = bversion.GetDefaultVersion()
		} else {
			dependenciesVersion = beatVersion
		}
		// add the snapshot suffix if needed
		dependenciesVersion += devtools.MaybeSnapshotSuffix()
	}
	log.Printf("Packaging with dependenciesVersion: %s", dependenciesVersion)

	dependencies, err := ExtractComponentsFromSelectedPkgSpecs(devtools.Packages)
	if err != nil {
		return fmt.Errorf("failed extracting dependencies: %w", err)
	}

	if mg.Verbose() {
		log.Printf("dependencies extracted from package specs: %v", dependencies)
	}

	keepArchive := os.Getenv("KEEP_ARCHIVE") != ""

	// download/copy all the necessary dependencies for packaging elastic-agent
	archivePath, dropPath, dependencies := collectPackageDependencies(mage.Platforms.Names(), dependenciesVersion, dependencies)

	// cleanup after build
	if !keepArchive {
		defer os.RemoveAll(archivePath)
		defer os.RemoveAll(dropPath)
	}
	defer os.Unsetenv(agentDropPath)

	// create flat dir
	flatPath := filepath.Join(dropPath, ".elastic-agent_flat")
	if mg.Verbose() {
		log.Printf("--- creating flat dir in .elastic-agent_flat")
	}
	os.MkdirAll(flatPath, 0o755)
	defer os.RemoveAll(flatPath)

	// extract all dependencies from their archives into flat dir
	flattenDependencies(mage.Platforms.Names(), dependenciesVersion, archivePath, dropPath, flatPath, manifestResponse, dependencies)

	// extract elastic-agent-core to be used for packaging
	err = extractAgentCoreForPackage(ctx, manifestResponse, dependenciesVersion)
	if err != nil {
		return err
	}

	// build package and test
	mg.SerialDeps(devtools.Package)
	return nil
}

// collectPackageDependencies performs the download (if it's an external dep), unpacking and move all the elastic-agent
// dependencies in the archivePath and dropPath
// NOTE: after the build is done the caller must:
// - delete archivePath and dropPath contents
// - unset AGENT_DROP_PATH environment variable
func collectPackageDependencies(platforms []string, packageVersion string, dependencies []packaging.BinarySpec) (archivePath, dropPath string, d []packaging.BinarySpec) {
	dropPath, found := os.LookupEnv(agentDropPath)

	// try not to shadow too many variables
	var err error

	// build deps only when drop is not provided
	if !found || len(dropPath) == 0 {
		// prepare new drop
		dropPath = filepath.Join("build", "distributions", "elastic-agent-drop")
		dropPath, err = filepath.Abs(dropPath)
		if err != nil {
			panic(fmt.Errorf("obtaining absolute path for default drop path: %w", err))
		}

		if mg.Verbose() {
			log.Printf(">> Creating drop-in folder %+v \n", dropPath)
		}
		archivePath = movePackagesToArchive(dropPath, platforms, packageVersion, dependencies)

		os.Setenv(agentDropPath, dropPath)

		if devtools.ExternalBuild == true {

			if mg.Verbose() {
				log.Print(">>> Using external builds to collect components")
			}

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

			for _, spec := range dependencies {
				for _, platform := range platforms {

					if !spec.SupportsPlatform(platform) {
						log.Printf(">>> Binary %s does not support %s, download skipped\n", spec.BinaryName, platform)
						continue
					}

					if mg.Verbose() {
						log.Printf(">>> Looking for component %s/%s", spec.BinaryName, platform)
					}
					if supportsAtLeastOnePackageType(platform, spec, devtools.SelectedPackageTypes) {
						targetPath := filepath.Join(archivePath, manifest.PlatformPackages[platform])
						os.MkdirAll(targetPath, 0o755)
						packageName := spec.GetPackageName(packageVersion, platform)
						if mg.Verbose() {
							log.Printf(">>> Downloading package %s component %s/%s", packageName, spec.BinaryName, platform)
						}
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
		}
	} else {
		archivePath = movePackagesToArchive(dropPath, platforms, packageVersion, dependencies)
	}

	// Only include components that support at least one of the selected package types
	dependencies = packaging.FilterComponents(dependencies, supportsSelectedPackageTypesFilter(platforms, devtools.SelectedPackageTypes))

	return archivePath, dropPath, dependencies
}

func supportsAtLeastOnePackageType(platform string, spec packaging.BinarySpec, packageTypes []devtools.PackageType) bool {
	for _, pkgType := range packageTypes {
		if mg.Verbose() {
			log.Printf(">>> Evaluating pkgType %v for component %s/%s", pkgType, spec.BinaryName, platform)
		}
		if !spec.SupportsPackageType(pkgcommon.PackageType(pkgType)) {
			continue
		}
		if mg.Verbose() {
			log.Printf(">>> Selecting component %s/%s because of pkgType %s", spec.BinaryName, platform, pkgType)
		}
		return true
	}
	log.Printf(">>> Component %s/%s not supported for any of the selected package types %v. Skipping...", spec.BinaryName, platform, packageTypes)
	return false
}

// supportsSelectedPackageTypesFilter returns a filter which will exclude components that do not support at least one of the selected package types
func supportsSelectedPackageTypesFilter(platforms []string, packageTypes []devtools.PackageType) packaging.ComponentFilter {
	return func(dep packaging.BinarySpec) bool {
		// If there are no package types set, return true to include all components by default
		if len(packageTypes) == 0 {
			return true
		}
		for _, platform := range platforms {
			if supportsAtLeastOnePackageType(platform, dep, packageTypes) {
				return true
			}
		}
		if mg.Verbose() {
			log.Printf(">>> Filtering out component %s as it doesn't support any selected package types %v", dep.BinaryName, packageTypes)
		}
		return false
	}
}

func removePythonWheels(matches []string, version string, dependencies []packaging.BinarySpec) []string {
	if hasSnapshotEnv() {
		version = fmt.Sprintf("%s-SNAPSHOT", version)
	}

	var wheels []string
	for _, spec := range dependencies {
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
func flattenDependencies(platforms []string, dependenciesVersion, archivePath, dropPath, flatPath string, manifestResponse *manifest.Build, dependencies []packaging.BinarySpec) {
	for _, pltf := range platforms {

		rp := manifest.PlatformPackages[pltf]

		targetPath := filepath.Join(archivePath, rp)
		versionedFlatPath := filepath.Join(flatPath, rp)
		versionedDropPath := filepath.Join(dropPath, rp)
		os.MkdirAll(targetPath, 0o755)
		os.MkdirAll(versionedFlatPath, 0o755)
		os.MkdirAll(versionedDropPath, 0o755)

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
		matches = removePythonWheels(matches, dependenciesVersion, dependencies)

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
			checksums = devtools.ChecksumsWithManifest(pltf, dependenciesVersion, versionedFlatPath, versionedDropPath, manifestResponse, dependencies)
		} else {
			checksums = devtools.ChecksumsWithoutManifest(pltf, dependenciesVersion, versionedFlatPath, versionedDropPath, dependencies)
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
	components, err := packaging.Components()
	if err != nil {
		return fmt.Errorf("retrieving defined components: %w", err)
	}
	elasticAgentCoreComponents := packaging.FilterComponents(components, packaging.WithProjectName(agentCoreProjectName), packaging.WithFIPS(devtools.FIPSBuild))

	if len(elasticAgentCoreComponents) != 1 {
		return fmt.Errorf(
			"found an unexpected number of elastic-agent-core components (should be 1) [projectName: %q, fips: %v]: %v",
			agentCoreProjectName,
			devtools.FIPSBuild,
			elasticAgentCoreComponents,
		)
	}

	elasticAgentCoreComponent := elasticAgentCoreComponents[0]

	branchInformation, err := findLatestBuildForBranch(ctx, baseURLForSnapshotDRA, branch)
	if err != nil {
		return fmt.Errorf("getting latest build for branch %q: %v", err)
	}

	// Create a dir with the buildID at <root>/build/core/<buildID>
	repositoryRoot, err := mage.ElasticBeatsDir()
	if err != nil {
		return fmt.Errorf("finding repository root: %w", err)
	}
	coreDownloadDir := filepath.Join(repositoryRoot, "build", "core")
	err = os.MkdirAll(coreDownloadDir, 0o770)
	if err != nil {
		return fmt.Errorf("creating %q directory: %w", err)
	}

	build, err := manifest.DownloadManifest(ctx, branchInformation.ManifestURL)
	if err != nil {
		return fmt.Errorf("downloading manifest from %q: %w", branchInformation.ManifestURL, err)
	}

	artifacts, err := downloadDRAArtifacts(ctx, &build, build.Version, coreDownloadDir, elasticAgentCoreComponent)
	if err != nil {
		return fmt.Errorf("downloading DRA artifacts from %q: %w", branchInformation.ManifestURL, err)
	}

	fmt.Println("Downloaded agent core DRAs:")
	for k := range artifacts {
		fmt.Println(filepath.Join(coreDownloadDir, k))
	}
	return nil
}

// PackageUsingDRA packages elastic-agent for distribution using Daily Released Artifacts specified in manifest.
func PackageUsingDRA(ctx context.Context) error {
	start := time.Now()
	defer func() { fmt.Println("package ran for", time.Since(start)) }()

	if len(devtools.Platforms) == 0 {
		return fmt.Errorf("elastic-agent package is expected to build at least one platform package")
	}

	// final package build
	mage.UseElasticAgentPackaging()

	// When MANIFEST_URL is not provided in the environment elastic-agent-core packages from build/distributions
	// will be used instead of pulling from the manifest.
	var err error
	var manifestResponse *manifest.Build
	var dependenciesVersion string
	manifestURL := os.Getenv(mage.ManifestUrlEnvVar)
	if manifestURL == "" {
		fmt.Println("NOTICE: No MANIFEST_URL was provided, using elastic-agent-core packages from build/distributions.")
	} else {
		var parsedVersion *version.ParsedSemVer
		manifestResponse, parsedVersion, err = downloadManifestAndSetVersion(ctx, devtools.ManifestURL)
		if err != nil {
			return fmt.Errorf("failed downloading manifest: %w", err)
		}
		dependenciesVersion = parsedVersion.VersionWithPrerelease()

		// fix the commit hash independently of the current commit hash on the branch
		agentCoreProject, ok := manifestResponse.Projects[agentCoreProjectName]
		if !ok {
			return fmt.Errorf("%q project not found in manifest %q", agentCoreProjectName, devtools.ManifestURL)
		}
		err = os.Setenv(mage.AgentCommitHashEnvVar, agentCoreProject.CommitHash)
		if err != nil {
			return fmt.Errorf("setting agent commit hash %q: %w", agentCoreProject.CommitHash, err)
		}
	}

	return packageAgent(ctx, dependenciesVersion, manifestResponse)
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

func downloadDRAArtifacts(ctx context.Context, build *manifest.Build, version string, draDownloadDir string, components ...packaging.BinarySpec) (map[string]manifest.Package, error) {
	err := os.MkdirAll(draDownloadDir, 0o770)
	if err != nil {
		return nil, fmt.Errorf("creating %q directory: %w", draDownloadDir, err)
	}

	// sync access to the downloadedArtifacts map
	mx := new(sync.Mutex)
	downloadedArtifacts := map[string]manifest.Package{}
	errGrp, errCtx := errgroup.WithContext(ctx)

	var downloaders []func() error

	for _, comp := range components {
		for _, platform := range devtools.Platforms.Names() {

			if !comp.SupportsPlatform(platform) {
				if mg.Verbose() {
					log.Printf("skipping download of %s/%s for platform %s as it's not supported", comp.ProjectName, comp.BinaryName, platform)
				}
				continue
			}

			project, ok := build.Projects[comp.ProjectName]
			if !ok {
				return nil, fmt.Errorf("project %q not found in manifest", comp.ProjectName)
			}

			if mg.Verbose() {
				log.Printf("build %q project %s packages: %+v", build.BuildID, comp.ProjectName, project)
			}

			packageName := comp.GetPackageName(version, platform)

			if packageSpec, ok := project.Packages[packageName]; ok {
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
						downloadedArtifacts[pkgName] = pkgDesc

						return nil
					}
				}(packageName, packageSpec)
				downloaders = append(downloaders, downloadFunc)
			} else {
				return nil, fmt.Errorf("package %q not found in project %q", packageName, comp.ProjectName)
			}

		}
	}

	for _, d := range downloaders {
		errGrp.Go(d)
	}

	return downloadedArtifacts, errGrp.Wait()
}

func extractAgentCoreForPackage(ctx context.Context, manifestResponse *manifest.Build, version string) error {
	components, err := packaging.Components()
	if err != nil {
		return fmt.Errorf("retrieving defined components: %w", err)
	}
	elasticAgentCoreComponents := packaging.FilterComponents(components, packaging.WithProjectName(agentCoreProjectName), packaging.WithFIPS(devtools.FIPSBuild))
	if len(elasticAgentCoreComponents) != 1 {
		return fmt.Errorf(
			"found an unexpected number of elastic-agent-core components (should be 1) [projectName: %q, fips: %v]: %v",
			agentCoreProjectName,
			devtools.FIPSBuild,
			elasticAgentCoreComponents,
		)
	}
	elasticAgentCoreComponent := elasticAgentCoreComponents[0]

	repositoryRoot, err := mage.ElasticBeatsDir()
	if err != nil {
		return fmt.Errorf("looking up for repository root: %w", err)
	}

	downloadDir := filepath.Join(repositoryRoot, "build", "core")

	var coreDownloadDir string
	if manifestResponse == nil {
		// Use the build elastic-agent-core packages from the build/distributions
		coreDownloadDir = filepath.Join(repositoryRoot, "build", "distributions")
	} else {
		// Download the artifacts from the manifest response with the buildID at <downloadDir>/<buildID>
		coreDownloadDir = filepath.Join(downloadDir, manifestResponse.BuildID)
		_, err = downloadDRAArtifacts(ctx, manifestResponse, version, coreDownloadDir, elasticAgentCoreComponent)
		if err != nil {
			return fmt.Errorf("downloading elastic-agent-core artifacts: %w", err)
		}
	}

	// Create extracted director, ensure it doesn't exist.
	const extractionSubdir = "extracted"
	extractDir := filepath.Join(downloadDir, extractionSubdir)
	_ = os.RemoveAll(extractDir) // ignore error

	// place the artifacts where the package.yml expects them (in 'build/dra/extracted/{{.GOOS}}-{{.Platform.Arch}}')
	for _, platform := range devtools.Platforms.Names() {
		if !elasticAgentCoreComponent.SupportsPlatform(platform) {
			continue
		}
		expectedPackageName := elasticAgentCoreComponent.GetPackageName(version, platform)

		// uncompress the archive first
		artifactFile := filepath.Join(coreDownloadDir, expectedPackageName)
		log.Printf("extracting artifact from %q into %q", artifactFile, extractDir)
		err = devtools.Extract(artifactFile, extractDir)
		if err != nil {
			return fmt.Errorf("extracting %q: %w", artifactFile, err)
		}

		// rename this directory to match the format expected by the core_source packaging target
		// this is 'build/dra/extracted/{{.GOOS}}-{{.Platform.Arch}}' in the repository
		targetArtifactName := elasticAgentCoreComponent.GetRootDir(version, platform)
		srcDir := filepath.Join(extractDir, targetArtifactName)
		dstDir := filepath.Join(extractDir, strings.Replace(platform, "/", "-", 1))
		_ = os.RemoveAll(dstDir) // ignore error, just can't exist before the rename
		log.Printf("renaming %q to %q", srcDir, dstDir)
		err := os.Rename(srcDir, dstDir)
		if err != nil {
			return fmt.Errorf("failed renaming %q to %q: %w", srcDir, dstDir, err)
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
		if strings.HasPrefix(filepath.Base(versionedDropPath), "windows") {
			componentFile += ".exe"
		}
		hash, err := devtools.GetSHA512Hash(filepath.Join(versionedDropPath, componentFile))
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf(">>> Computing hash for %q failed: %s\n", componentFile, err)
			return fmt.Errorf("cannot generate SHA512 for %q: %s", componentFile, err)
		} else if err != nil {
			return err
		}

		checksums[componentFile] = hash
	}

	content, err := yamlChecksum(checksums)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(versionedDropPath, checksumFilename), content, 0o644)
}

// movePackagesToArchive Create archive folder and move any pre-existing artifacts into it.
func movePackagesToArchive(dropPath string, platforms []string, packageVersion string, dependencies []packaging.BinarySpec) string {
	archivePath := filepath.Join(dropPath, "archives")
	os.MkdirAll(archivePath, 0o755)

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
		for _, pltf := range platforms {
			packageSuffix := manifest.PlatformPackages[pltf]
			if mg.Verbose() {
				log.Printf("--- Evaluating moving dependency %s to archive path %s\n", f, archivePath)
			}
			// if the matched file name does not contain the platform suffix and it's not a platform-independent package, skip it
			if !strings.Contains(f, packageSuffix) && !isPlatformIndependentPackage(f, packageVersion, dependencies) {
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
			if err := os.MkdirAll(targetDir, 0o750); err != nil {
				fmt.Printf("warning: failed to create directory %s: %s", targetDir, err)
			}

			// Platform-independent packages need to be placed in the archive sub-folders for all platforms, copy instead of moving
			if isPlatformIndependentPackage(f, packageVersion, dependencies) {
				if mg.Verbose() {
					log.Printf("copying %s to %s as it is a platform independent package", f, packageVersion)
				}
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

func isPlatformIndependentPackage(f string, packageVersion string, dependencies []packaging.BinarySpec) bool {
	fileBaseName := filepath.Base(f)
	if mg.Verbose() {
		log.Printf("isPlatformIndependentPackage(%s, %s, %v)", f, packageVersion, dependencies)
	}
	for _, spec := range dependencies {
		if mg.Verbose() {
			log.Printf("evaluating if %s is a platform independent package", f)
		}
		packageName := spec.GetPackageName(packageVersion, "")
		// as of now only python wheels packages are platform-independent
		if mg.Verbose() {
			log.Printf("checking expected package name %s against actual file name %s", packageName, fileBaseName)
		}
		if spec.PythonWheel && (fileBaseName == packageName || fileBaseName == packageName+sha512FileExt) {
			if mg.Verbose() {
				log.Printf("%s is a platform independent package", f)
			}
			return true
		}
	}
	if mg.Verbose() {
		log.Printf("%s is NOT a platform independent package", f)
	}
	return false
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

	if fipsFlag, fipsFound := os.LookupEnv(fipsEnv); fipsFound {
		if fips, err := strconv.ParseBool(fipsFlag); err == nil && fips {
			vars["github.com/elastic/elastic-agent/internal/pkg/release.fips"] = "true"
		}
	}

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

// Ironbank packages elastic-agent for the IronBank distribution, relying on the
// binaries having already been built.
//
// Use SNAPSHOT=true to build snapshots.
func Ironbank() error {
	fmt.Println("--- Package Ironbank distribution")
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

	if _, err := os.Stat(devtools.DistributionsDir); os.IsNotExist(err) {
		err := os.MkdirAll(devtools.DistributionsDir, 0o750)
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
	tarGzFile := filepath.Join("..", "..", devtools.DistributionsDir, ironbank+".tar.gz")

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
	ver, _ := devtools.BeatQualifiedVersion()
	defaultBinaryName := "{{.Name}}-ironbank-{{.Version}}{{if .Snapshot}}-SNAPSHOT{{end}}"
	outputDir, _ := devtools.Expand(defaultBinaryName+"-docker-build-context", map[string]interface{}{
		"Name":    "elastic-agent",
		"Version": ver,
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
	return errors.Join(
		define.ValidateDir("testing/integration/ess"),
		define.ValidateDir("testing/integration/serverless"),
		define.ValidateDir("testing/integration/beats/serverless"),
		define.ValidateDir("testing/integration/leak"),
		define.ValidateDir("testing/integration/k8s"),
	)
}

// Local runs only the integration tests that support local mode
// it takes as argument the test name to run or all if we want to run them all.
func (Integration) Local(ctx context.Context, testName string) error {
	if shouldBuildAgent() {
		// need only local package for current platform
		devtools.Platforms = devtools.Platforms.Select(fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))
		mg.Deps(Package)
	}
	mg.Deps(Build.TestFakeComponent)

	// clean the .agent-testing/local so this run will use the latest build
	_ = os.RemoveAll(".agent-testing/local")

	// run the integration tests but only run test that can run locally
	params := devtools.DefaultGoTestIntegrationArgs()
	params.Tags = append(params.Tags, "local")
	params.Packages = []string{
		"github.com/elastic/elastic-agent/testing/integration/...",
	}

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
	return integRunner(ctx, "testing/integration/ess", false, "")
}

// Matrix runs integration tests on a matrix of all supported remote hosts
func (Integration) Matrix(ctx context.Context) error {
	return integRunner(ctx, "testing/integration/ess", true, "")
}

// Single runs single integration test on remote host
func (Integration) Single(ctx context.Context, testName string) error {
	return integRunner(ctx, "testing/integration/ess", false, testName)
}

// TestServerless runs the integration tests defined in testing/integration/serverless
func (i Integration) TestServerless(ctx context.Context) error {
	return i.testServerless(ctx, false, "")
}

// TestServerlessSingle runs a single integration test defined in testing/integration/serverless
func (i Integration) TestServerlessSingle(ctx context.Context, testName string) error {
	return i.testServerless(ctx, false, testName)
}

func (i Integration) testServerless(ctx context.Context, matrix bool, testName string) error {
	err := os.Setenv("STACK_PROVISIONER", "serverless")
	if err != nil {
		return fmt.Errorf("error setting serverless stack env var: %w", err)
	}

	return integRunner(ctx, "testing/integration/serverless", matrix, testName)
}

// TestKubernetes runs the integration tests defined in testing/integration/k8s
func (i Integration) TestKubernetes(ctx context.Context) error {
	return i.testKubernetes(ctx, false, "")
}

// TestKubernetesSingle runs a single integration test defined in testing/integration/k8s
func (i Integration) TestKubernetesSingle(ctx context.Context, testName string) error {
	return i.testKubernetes(ctx, false, testName)
}

// TestKubernetesMatrix runs a matrix of integration tests defined in testing/integration/k8s
func (i Integration) TestKubernetesMatrix(ctx context.Context) error {
	return i.testKubernetes(ctx, true, "")
}

func (i Integration) testKubernetes(ctx context.Context, matrix bool, testName string) error {
	mg.Deps(Integration.BuildKubernetesTestData)
	// invoke integration tests
	if err := os.Setenv("TEST_GROUPS", "kubernetes"); err != nil {
		return err
	}

	return integRunner(ctx, "testing/integration/k8s", matrix, testName)
}

// BuildKubernetesTestData builds the test data required to run k8s integration tests
func (Integration) BuildKubernetesTestData(ctx context.Context) error {
	// build the dependencies for the elastic-agent helm chart
	mg.Deps(Helm.BuildDependencies)

	// download opentelemetry-kube-stack helm chart
	kubeStackHelmChartTargetPath := filepath.Join("testing", "integration", "k8s", k8s.KubeStackChartPath)
	if err := os.RemoveAll(kubeStackHelmChartTargetPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %q: %w", kubeStackHelmChartTargetPath, err)
	}

	kubeStackHelmChartTargetDir := filepath.Dir(kubeStackHelmChartTargetPath)
	downloadedKubeStackHelmChartPath, err := devtools.DownloadFile(k8s.KubeStackChartURL, kubeStackHelmChartTargetDir)
	if err != nil {
		return fmt.Errorf("failed to download opentelemetry-kube-stack helm chart %q: %w", k8s.KubeStackChartURL, err)
	}
	if err := devtools.Extract(downloadedKubeStackHelmChartPath, kubeStackHelmChartTargetDir); err != nil {
		return fmt.Errorf("failed to extract opentelemetry-kube-stack helm chart %q: %w", downloadedKubeStackHelmChartPath, err)
	}
	if err := os.Remove(downloadedKubeStackHelmChartPath); err != nil {
		return fmt.Errorf("failed to remove downloaded opentelemetry-kube-stack helm chart %q: %w", downloadedKubeStackHelmChartPath, err)
	}

	// render elastic-agent-standalone kustomize
	kustomizeYaml, err := kubernetes.RenderKustomize(ctx, filepath.Join("deploy", "kubernetes", "elastic-agent-kustomize", "default", "elastic-agent-standalone"))
	if err != nil {
		return fmt.Errorf("failed to render kustomize: %w", err)
	}
	if err := os.WriteFile(filepath.Join("testing", "integration", "k8s", k8s.AgentKustomizePath), kustomizeYaml, 0o644); err != nil {
		return fmt.Errorf("failed to write kustomize.yaml: %w", err)
	}

	return nil
}

// UpdateVersions runs an update on the `.agent-versions.yml` fetching
// the latest version list from the artifact API.
func (Integration) UpdateVersions(ctx context.Context) error {
	agentVersion, err := version.ParseVersion(bversion.Agent)
	if err != nil {
		return fmt.Errorf("failed to parse agent version %s: %w", bversion.Agent, err)
	}

	// maxSnapshots is the maximum number of snapshots from
	// releases branches we want to include in the snapshot list
	maxSnapshots := 2

	branches, err := git.GetReleaseBranches(ctx)
	if err != nil {
		return fmt.Errorf("failed to list release branches: %w", err)
	}

	// limit the number of snapshot branches to the maxSnapshots
	targetSnapshotBranches := branches[:maxSnapshots]
	var ltsBranches []string

	// if we have a newer version of the agent, we want to include the latest snapshot from 8.19 LTS branch
	if agentVersion.Major() > 8 || agentVersion.Major() == 8 && agentVersion.Minor() > 19 {
		// order is important
		ltsBranches = []string{"8.19"}
	}

	// need to include the LTS branches, sort them and remove duplicates
	targetSnapshotBranches = append(targetSnapshotBranches, ltsBranches...)
	sort.Slice(targetSnapshotBranches, git.Less(targetSnapshotBranches))
	targetSnapshotBranches = slices.Compact(targetSnapshotBranches)

	// uncomment if want to have the current version snapshot on the list as well
	// branches = append([]string{"master"}, branches...)

	reqs := upgradetest.VersionRequirements{
		UpgradeToVersion: bversion.Agent,
		CurrentMajors:    1,
		PreviousMinors:   2,
		PreviousMajors:   2,
		SnapshotBranches: targetSnapshotBranches,
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
	file, err := os.OpenFile(upgradetest.AgentVersionsFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
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
	currentReleaseBranch, err := git.GetCurrentReleaseBranch(ctx)
	if err != nil {
		return fmt.Errorf("failed to identify the current release branch: %w", err)
	}

	branchInformation, err := findLatestBuildForBranch(ctx, baseURLForSnapshotDRA, currentReleaseBranch)
	if err != nil {
		return fmt.Errorf("failed to get latest build for branch %q: %w", currentReleaseBranch, err)
	}

	// If a release is available with the same core version as the latest snapshot, use the release. This can
	// happen after a new release, before a stack snapshot is available. In that event, older snapshots might not be
	// available.
	var stackVersion, stackBuildId string
	releasesResponse, err := devtools.FetchStackReleases(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch stack releases: %w", err)
	}
	latestReleaseForBranch := releasesResponse.GetLatestPatchForMinor(currentReleaseBranch)
	if latestReleaseForBranch != nil && strings.HasPrefix(branchInformation.Version, latestReleaseForBranch.Version) {
		stackVersion = latestReleaseForBranch.Version
		stackBuildId = ""
	} else {
		stackVersion = branchInformation.Version
		stackBuildId = fmt.Sprintf("%s-SNAPSHOT", branchInformation.BuildID)
	}

	err = devtools.UpdatePackageVersion(
		branchInformation.Version, branchInformation.BuildID, stackVersion, stackBuildId,
		branchInformation.ManifestURL, branchInformation.SummaryURL)
	if err != nil {
		return fmt.Errorf("failed to write package version: %w", err)
	}

	packageVersionBytes, err := os.ReadFile(devtools.PackageVersionFilename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	fmt.Println(string(packageVersionBytes))

	return nil
}

var stateDir = ".integration-cache"

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
			{"Integrations Server", stack.IntegrationsServer},
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
		return runner.StateInstance{}, fmt.Errorf("cannot list VMs: %w", err)
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

	fmt.Fprintf(f, "export INTEGRATIONS_SERVER_HOST=\"%s\"\n", stack.IntegrationsServer)

	return nil
}

// PrintState prints details about cloud stacks and VMs
func (Integration) PrintState() {
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
		return fmt.Errorf("cannot list VMs: %w", err)
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
		return fmt.Errorf("cannot get VM: %w", err)
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

// TestBeatServerless runs beats-oriented serverless tests
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
	return integRunner(ctx, "testing/integration/beats/serverless", false, "TestBeatsServerless")
}

// TestForResourceLeaks runs the integration tests defined in testing/integration/leak
func (i Integration) TestForResourceLeaks(ctx context.Context) error {
	return i.testForResourceLeaks(ctx, false, "")
}

// TestForResourceLeaksSingle runs a single integration test defined in testing/integration/leak
func (i Integration) TestForResourceLeaksSingle(ctx context.Context, testName string) error {
	return i.testForResourceLeaks(ctx, false, testName)
}

func (i Integration) testForResourceLeaks(ctx context.Context, matrix bool, testName string) error {
	return integRunner(ctx, "testing/integration/leak", matrix, testName)
}

// TestOnRemote shouldn't be called locally (called on remote host to perform testing)
func (Integration) TestOnRemote(ctx context.Context) error {
	mg.Deps(Build.TestFakeComponent)
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
	batches, err := define.DetermineBatches("testing/integration/ess", goTestFlags, "integration")
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

func integRunner(ctx context.Context, testDir string, matrix bool, singleTest string) error {
	if _, ok := ctx.Deadline(); !ok {
		// If the context doesn't have a timeout (usually via the mage -t option), give it one.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, goProvisionAndTestTimeout)
		defer cancel()
	}

	for {
		failedCount, err := integRunnerOnce(ctx, matrix, testDir, singleTest)
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

func integRunnerOnce(ctx context.Context, matrix bool, testDir string, singleTest string) (int, error) {
	goTestFlags := os.Getenv("GOTEST_FLAGS")

	batches, err := define.DetermineBatches(testDir, goTestFlags, "integration")
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
	err = writeFile("build/TEST-go-integration.out", results.Output, 0o644)
	if err != nil {
		return 0, fmt.Errorf("error writing test out file: %w", err)
	}
	err = writeFile("build/TEST-go-integration.out.json", results.JSONOutput, 0o644)
	if err != nil {
		return 0, fmt.Errorf("error writing test out json file: %w", err)
	}
	err = writeFile("build/TEST-go-integration.xml", results.XMLOutput, 0o644)
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
		Identifier: fmt.Sprintf("at-%s", strings.ReplaceAll(strings.Split(email, "@")[0], ".", "-")),
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
	_ = os.MkdirAll(diagDir, 0o755)

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
			return fmt.Errorf("unable to authenticate user: %w", err)
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
	serviceAcctName := fmt.Sprintf("%s-agent-testing", strings.ReplaceAll(parts[0], ".", "-"))
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
		if err := os.MkdirAll(filepath.Dir(essAPIKeyFile), 0o700); err != nil {
			return fmt.Errorf("unable to create ESS config directory: %w", err)
		}

		if err := os.WriteFile(essAPIKeyFile, nil, 0o600); err != nil {
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
	if err := os.WriteFile(essAPIKeyFile, []byte(essAPIKey), 0o600); err != nil {
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

// GolangCrossBuild builds the elastic-otel-collector binary in the golang-crossbuild container.
// Don't call directly; called from otel:crossBuild.
func (Otel) GolangCrossBuild() error {
	mg.Deps(EnsureCrossBuildOutputDir)

	params := devtools.DefaultGolangCrossBuildArgs()
	params.Name = "elastic-otel-collector-" + mage.Platform.GOOS + "-" + mage.Platform.Arch
	params.OutputDir = "build/golang-crossbuild"
	params.WorkDir = "internal/edot"
	params.Package = "."
	params.ExtraFlags = append(params.ExtraFlags, "-tags=agentbeat")
	injectBuildVars(params.Vars)

	// embedded packetbeat is only included in a non-FIPS build
	if !mage.FIPSBuild {
		// requires the NPCAP installer on Windows
		// ending '/' is required or the installer will not be copied to the correct location
		if err := xpacketbeat.CopyNPCAPInstaller("beats/x-pack/packetbeat/npcap/installer/"); err != nil {
			// to allow local builds for Windows, this is allowed to fail
			fmt.Printf("WARNING: Running packetbeat on Windows will fail, as no npcap installer will be embedded\n")
			fmt.Printf("WARNING: Failed to copy npcap installer for Windows: %s\n", err)
		}

		// requires custom CGO_LDFLAGS and CGO_CFLAGS
		packetBeatArgs := packetbeat.GolangCrossBuildArgs()
		if params.Env == nil {
			params.Env = map[string]string{}
		}
		cgoLdflags, ok := packetBeatArgs.Env["CGO_LDFLAGS"]
		if ok {
			_, exists := params.Env["CGO_LDFLAGS"]
			if exists {
				return fmt.Errorf("CGO_LDFLAGS already exists and packetbeat CGO_LDFLAGS will overwrite")
			}
			params.Env["CGO_LDFLAGS"] = cgoLdflags
		}
		cgoCflags, ok := packetBeatArgs.Env["CGO_CFLAGS"]
		if ok {
			_, exists := params.Env["CGO_CFLAGS"]
			if exists {
				return fmt.Errorf("CGO_CFLAGS already exists and packetbeat CGO_CFLAGS will overwrite")
			}
			params.Env["CGO_CFLAGS"] = cgoCflags
		}
	}

	if err := devtools.GolangCrossBuild(params); err != nil {
		return err
	}

	return nil
}

// npcapImageSelector is similar to xpacketbeat.ImageSelector, using a single variable to enable it. Sadly
// xpacketbeat.ImageSelector cannot be used directly because it will use its own devtools that comes from the beats
// repository and will duplicate global state that is not correct for the elastic-agent.
func npcapImageSelector(platform string) (string, error) {
	image, err := devtools.CrossBuildImage(platform)
	if err != nil {
		return "", err
	}
	if os.Getenv("WINDOWS_NPCAP") != "true" {
		return image, nil
	}
	if platform == "windows/amd64" {
		image = strings.ReplaceAll(image, "beats-dev", "observability-ci") // Temporarily work around naming of npcap image.
		image = strings.ReplaceAll(image, "main", "npcap-"+xpacketbeat.NpcapVersion+"-debian11")
	}
	return image, nil
}

// CrossBuild builds the elastic-otel-collector binary in the golang-crossbuild container.
func (Otel) CrossBuild() error {
	mg.Deps(EnsureCrossBuildOutputDir)

	// Download modules from internal/edot before crossbuilding.
	// The crossbuild process mounts the host's module cache read-only into the container,
	// so all dependencies must be downloaded before the build starts.
	// internal/edot has its own go.mod with different dependencies than the main module.
	if mage.CrossBuildMountModcache {
		fmt.Println(">> Downloading modules for internal/edot")
		if err := sh.Run("go", "-C", "internal/edot", "mod", "download"); err != nil {
			return fmt.Errorf("failed to download modules for internal/edot: %w", err)
		}
	}

	opts := []devtools.CrossBuildOption{devtools.WithName("elastic-otel-collector"), devtools.WithTarget("otel:golangCrossBuild")}

	// embedded packetbeat is only included in a non-FIPS build
	if !mage.FIPSBuild {
		// download the NPCAP installer
		mg.SerialDeps(xpacketbeat.GetNpcapInstallerFn(filepath.Join("beats", "x-pack", "packetbeat")))
		// use the npcap build image for windows
		opts = append(opts, devtools.ImageSelector(npcapImageSelector))
	}

	return devtools.CrossBuild(opts...)
}

func (Otel) Readme() error {
	fmt.Println(">> Building internal/edot/README.md")

	readmeTmpl := filepath.Join("internal", "edot", "templates", "README.md.tmpl")
	readmeOut := filepath.Join("internal", "edot", "README.md")

	// read README template
	tmpl, err := template.ParseFiles(readmeTmpl)
	if err != nil {
		return fmt.Errorf("failed to parse README template: %w", err)
	}

	data, err := otel.GetOtelDependencies(filepath.Join("internal", "edot", "go.mod"))
	if err != nil {
		return fmt.Errorf("Failed to get OTel dependencies: %w", err)
	}

	// resolve template
	out, err := os.OpenFile(readmeOut, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
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

func (Otel) MetricbeatPrepareLightModules() error {
	return metricbeat.PrepareLightModulesPackaging(
		filepath.Join("beats", "x-pack", "metricbeat", "module"), // x-pack/metricbeat
		filepath.Join("beats", "metricbeat", "module"),           // metricbeat (oss)
	)
}

// StripOsquerydGolangCrossBuild runs inside of the cross-build container.
// Don't call directly; this is called from otel:osquerybeatFetchOsqueryDistros.
func (Otel) StripOsquerydGolangCrossBuild() error {
	for _, platform := range devtools.Platforms {
		if platform.GOOS() != os.Getenv("GOOS") || platform.Arch() != os.Getenv("GOARCH") {
			// only run on specific os/arch combination
			continue
		}

		var stripCmd string
		var binaryPath string
		switch platform.Arch() {
		case "amd64":
			stripCmd = "x86_64-linux-gnu-strip"
			binaryPath = "build/data/install/linux/amd64/osqueryd"
		case "arm64":
			stripCmd = "aarch64-linux-gnu-strip"
			binaryPath = "build/data/install/linux/arm64/osqueryd"
		default:
			return fmt.Errorf("unsupported architecture %s", platform.Arch())
		}

		err := sh.RunV(stripCmd, binaryPath)
		if err != nil {
			return fmt.Errorf("failed to strip osqueryd: %w", err)
		}
	}

	return nil
}

func (Otel) OsquerybeatFetchOsqueryDistros() error {
	mg.Deps(osquerybeat.FetchOsqueryDistros)

	// crossBuild container is used to strip the osqueryd binary (strip needs to be built for the specific
	// os/architecture for it to work properly)
	opts := []devtools.CrossBuildOption{devtools.WithName("strip-osqueryd"), devtools.WithTarget("otel:stripOsquerydGolangCrossBuild"), devtools.ForPlatforms("linux")}
	return devtools.CrossBuild(opts...)
}

// PrepareBeats converts the beats submodule's .git file to a real .git directory.
// Git submodules by default have a .git file that points to the parent repo's .git/modules/<submodule> directory.
// When running  crossbuild in Docker, only the submodule directory is mounted, so the reference to the parent's
// .git/modules breaks. This function copies the actual git directory into the submodule so it works standalone
// in Docker.
func (Otel) PrepareBeats() error {
	beatsGitPath := filepath.Join("beats", ".git")

	// check if .git is a file (submodule) or directory (already converted)
	info, err := os.Lstat(beatsGitPath)
	if err != nil {
		return fmt.Errorf("failed to stat beats/.git: %w", err)
	}
	if info.IsDir() {
		// already a directory
		return nil
	}

	// read the .git file to get the gitdir path
	content, err := os.ReadFile(beatsGitPath)
	if err != nil {
		return fmt.Errorf("failed to read beats/.git file: %w", err)
	}
	gitdirLine := strings.TrimSpace(string(content))
	if !strings.HasPrefix(gitdirLine, "gitdir: ") {
		return fmt.Errorf("unexpected beats/.git content: %s", gitdirLine)
	}
	gitdirRelPath := strings.TrimPrefix(gitdirLine, "gitdir: ")

	// verify the source git directory exists
	gitdirAbsPath := filepath.Join("beats", gitdirRelPath)
	if _, err := os.Stat(gitdirAbsPath); err != nil {
		return fmt.Errorf("git modules directory not found at %s: %w", gitdirAbsPath, err)
	}

	fmt.Printf(">> Converting beats submodule .git file to directory (source: %s)\n", gitdirAbsPath)

	// remove the core.worktree config from the source before copying.
	// use git config -f to edit the file directly without needing a valid worktree.
	// otherwise it would error with "fatal: cannot chdir to '../../../beats': No such file or directory"
	sourceConfigPath := filepath.Join(gitdirAbsPath, "config")
	if err := sh.Run("git", "config", "-f", sourceConfigPath, "--unset", "core.worktree"); err != nil {
		// exit code 5 means the key was not found, which is fine
		if sh.ExitStatus(err) != 5 {
			return fmt.Errorf("failed to unset core.worktree in git config: %w", err)
		}
	}

	// remove the .git file and copy the directory
	if err := os.Remove(beatsGitPath); err != nil {
		return fmt.Errorf("failed to remove beats/.git file: %w", err)
	}
	copyOpts := filecopy.Options{
		Skip: func(info os.FileInfo, src, dest string) (bool, error) {
			switch {
			case (info.Mode() & fs.ModeSocket) != 0:
				return true, nil
			default:
				return false, nil
			}
		},
	}
	if err := filecopy.Copy(gitdirAbsPath, beatsGitPath, copyOpts); err != nil {
		return fmt.Errorf("failed to copy git directory: %w", err)
	}

	fmt.Println(">> Successfully converted beats/.git to a directory")
	return nil
}

func (Otel) OsquerybeatCrossBuildExt() error {
	mg.Deps(Otel.PrepareBeats)
	fmt.Println("--- CrossBuild osquery-extension")
	osquerybeatDir := filepath.Join("beats", "x-pack", "osquerybeat")
	err := sh.RunV("mage", "-d", osquerybeatDir, "crossBuildExt")
	if err != nil {
		return fmt.Errorf("failed to run mage -d %s crossBuildExt: %w", err)
	}
	return nil
}

func (Otel) Prepare() {
	deps := []interface{}{Otel.MetricbeatPrepareLightModules}
	if !mage.FIPSBuild {
		// fips build doesn't embed osquerybeat
		deps = append(deps, Otel.OsquerybeatFetchOsqueryDistros, Otel.OsquerybeatCrossBuildExt)
	}
	mg.Deps(deps...)
}

type Helm mg.Namespace

// RenderExamples runs the equivalent of `helm template` and `helm lint`
// for the examples of the Elastic Helm chart which are located at
// `deploy/helm/elastic-agent/examples` directory.
func (h Helm) RenderExamples() error {
	mg.SerialDeps(h.BuildDependencies)

	settings := cli.New() // Helm CLI settings
	actionConfig := &action.Configuration{}

	err := actionConfig.Init(settings.RESTClientGetter(), "default", "",
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

		helmChart, err := loader.Load(helmChartPath)
		if err != nil {
			return fmt.Errorf("failed to load helm chart: %w", err)
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

		lintAction := action.NewLint()
		lintResult := lintAction.Run([]string{helmChartPath}, helmValues)
		if len(lintResult.Errors) > 0 {
			return fmt.Errorf("failed to lint helm chart for example %s: %w", exampleFullPath, errors.Join(lintResult.Errors...))
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
			return fmt.Errorf("failed to write rendered manifest %q: %w", renderedManifestPath, err)
		}

		f, err := os.Open(renderedManifestPath)
		if err != nil {
			return fmt.Errorf("failed to open rendered manifest %q: %w", renderedManifestPath, err)
		}

		objs, err := kubernetes.LoadFromYAML(bufio.NewReader(f))
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("failed to load k8s objects from rendered manifest %q: %w", renderedManifestPath, err)
		}

		if len(objs) == 0 {
			return fmt.Errorf("rendered manifest %q is empty", renderedManifestPath)
		}
	}

	return nil
}

// UpdateAgentVersion updates the agent version in the Elastic-Agent and EDOT-Collector Helm charts.
func (Helm) UpdateAgentVersion() error {
	agentVersion := bversion.GetParsedAgentPackageVersion().CoreVersion()
	agentSnapshotVersion := agentVersion + "-SNAPSHOT"
	// until the Helm chart reaches GA this remains with -SNAPSHOT suffix
	// that's to differentiate it from the released charts in the Helm repo using
	// the same versioning scheme as the Unified Release process.
	agentChartVersion := agentVersion + "-SNAPSHOT"

	for yamlFile, keyVals := range map[string][]struct {
		key   string
		value string
	}{
		// values file for elastic-agent Helm Chart
		filepath.Join(helmChartPath, "values.yaml"): {
			{"agent.version", agentVersion},
			// always use the SNAPSHOT version for image tag
			// for the chart that resides in the git repo
			{"agent.image.tag", agentSnapshotVersion},
		},
		// Chart.yaml for elastic-agent Helm Chart
		filepath.Join(helmChartPath, "Chart.yaml"): {
			{"appVersion", agentVersion},
			{"version", agentChartVersion},
		},
		// edot-collector values file for kube-stack Helm Chart
		filepath.Join(helmOtelChartPath, "values.yaml"): {
			{"defaultCRConfig.image.tag", agentVersion},
		},
		filepath.Join(helmMOtelChartPath, "values.yaml"): {
			{"defaultCRConfig.image.tag", agentVersion},
		},
		filepath.Join(helmMOtelChartPath, "logs-values.yaml"): {
			{"defaultCRConfig.image.tag", agentVersion},
		},
	} {
		if err := updateYamlFile(yamlFile, keyVals...); err != nil {
			return fmt.Errorf("failed to update agent version: %w", err)
		}
	}

	return nil
}

// Lint lints the Elastic-Agent Helm chart.
func (h Helm) Lint() error {
	mg.SerialDeps(h.BuildDependencies)

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

func updateYamlFile(path string, keyVal ...struct {
	key   string
	value string
},
) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

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

	for _, kv := range keyVal {
		if err := updateYamlNodes(rootNode.Content[0], kv.value, strings.Split(kv.key, ".")...); err != nil {
			return fmt.Errorf("failed to update agent version: %w", err)
		}
	}

	// Truncate values file
	file, err := os.Create(path)
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

func (Helm) ensureRepository(repoName, repoURL string, settings *cli.EnvSettings) error {
	repoFile := settings.RepositoryConfig
	// Load existing repositories
	file, err := repo.LoadFile(repoFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			file = repo.NewFile()
		} else {
			return fmt.Errorf("could not load Helm repository config: %w", err)
		}
	}

	// Check if the repository is already added
	for _, entry := range file.Repositories {
		if entry.URL == repoURL {
			// repository already exists
			return nil
		}
	}

	// Add the repository
	entry := &repo.Entry{
		Name: repoName,
		URL:  repoURL,
	}

	chartRepo, err := repo.NewChartRepository(entry, getter.All(settings))
	if err != nil {
		return fmt.Errorf("could not create repo %s: %w", repoURL, err)
	}

	_, err = chartRepo.DownloadIndexFile()
	if err != nil {
		return fmt.Errorf("could not download index file for repo %s: %w", repoURL, err)
	}

	file.Update(entry)
	if err := file.WriteFile(repoFile, 0o644); err != nil {
		return fmt.Errorf("could not write Helm repository config: %w", err)
	}

	return nil
}

func (h Helm) handleDependencies(update bool) error {
	settings := cli.New()
	settings.SetNamespace("")
	actionConfig := &action.Configuration{}

	chartFilePath := filepath.Join(helmChartPath, "Chart.yaml")
	chartFile, err := os.ReadFile(chartFilePath)
	if err != nil {
		return fmt.Errorf("could not read %q: %w", chartFilePath, err)
	}

	dependencies := struct {
		Entry []struct {
			Name       string `yaml:"name"`
			Repository string `yaml:"repository"`
		} `yaml:"dependencies"`
	}{}

	if err := os.RemoveAll(filepath.Join(helmChartPath, "charts")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("could not remove %s/charts: %w", helmChartPath, err)
	}

	err = yaml.Unmarshal(chartFile, &dependencies)
	if err != nil {
		return fmt.Errorf("could not unmarshal %s/Chart.yaml: %w", helmChartPath, err)
	}

	for _, dep := range dependencies.Entry {
		err := h.ensureRepository(dep.Name, dep.Repository, settings)
		if err != nil {
			return err
		}
	}

	err = actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), "",
		func(format string, v ...interface{}) {})
	if err != nil {
		return fmt.Errorf("failed to init helm action config: %w", err)
	}

	client := action.NewDependency()

	registryClient, err := registry.NewClient(
		registry.ClientOptDebug(settings.Debug),
		registry.ClientOptEnableCache(true),
		registry.ClientOptWriter(os.Stderr),
		registry.ClientOptCredentialsFile(settings.RegistryConfig),
	)
	if err != nil {
		return fmt.Errorf("failed to create helm registry client: %w", err)
	}

	buffer := bytes.Buffer{}

	man := &downloader.Manager{
		Out:              bufio.NewWriter(&buffer),
		ChartPath:        helmChartPath,
		Keyring:          client.Keyring,
		SkipUpdate:       true,
		Getters:          getter.All(settings),
		RegistryClient:   registryClient,
		RepositoryConfig: settings.RepositoryConfig,
		RepositoryCache:  settings.RepositoryCache,
		Debug:            settings.Debug,
	}
	if client.Verify {
		man.Verify = downloader.VerifyIfPossible
	}

	if update {
		if err = man.Update(); err != nil {
			return fmt.Errorf("failed to build helm dependencies: %w", err)
		}
	} else {
		if err = man.Build(); err != nil {
			return fmt.Errorf("failed to update helm dependencies: %w", err)
		}
	}

	subChartDir := filepath.Join(helmChartPath, "charts")

	subChartArchives, err := filepath.Glob(filepath.Join(subChartDir, "*.tgz"))
	if err != nil {
		return fmt.Errorf("failed to get subchart archives: %w", err)
	}

	if len(subChartArchives) != len(dependencies.Entry) {
		return fmt.Errorf("expected %d subchart archives, got %d", len(dependencies.Entry), len(subChartArchives))
	}

	for _, subChartArchive := range subChartArchives {
		err := mage.Extract(subChartArchive, subChartDir)
		if err != nil {
			return fmt.Errorf("failed to extract %q: %w", subChartArchive, err)
		}

		err = os.Remove(subChartArchive)
		if err != nil {
			return fmt.Errorf("failed to remove %q: %w", subChartArchive, err)
		}
	}

	return nil
}

// BuildDependencies builds the dependencies for the Elastic-Agent Helm chart.
//
// This is a custom implementation that extends the functionality of `helm dependency update`.
// The standard Helm command assumes that all dependency repositories have been added beforehand
// via `helm repo add`, otherwise it fails. This method improves usability by ensuring all
// required repositories are added automatically before resolving dependencies.
//
// Furthermore, `helm dependency update` downloads dependencies as `.tgz` archives into the `charts/`
// directory but does not untar them. For our integration tests, we require the subcharts to be
// extracted. This method downloads and extracts each `.tgz` archive and removes the archive afterward,
// so that only the extracted subcharts remain in the `charts/` directory.
func (h Helm) BuildDependencies() error {
	return h.handleDependencies(false)
}

func (h Helm) UpdateDependencies() error {
	return h.handleDependencies(true)
}

// Package packages the Elastic-Agent Helm chart. Note that you need to set SNAPSHOT="false" to build a production-ready package.
func (h Helm) Package() error {
	fmt.Println("--- Package Helm chart distribution")
	mg.SerialDeps(h.BuildDependencies)

	// need to explicitly set SNAPSHOT="false" to produce a production-ready package
	productionPackage := os.Getenv("SNAPSHOT") == "false"

	agentVersion := bversion.GetParsedAgentPackageVersion()
	agentCoreVersion := agentVersion.CoreVersion()
	agentImageTag := agentCoreVersion
	if !productionPackage {
		// always use the SNAPSHOT version for image tag if not a production package
		agentImageTag = agentImageTag + "-SNAPSHOT"
	}

	agentChartVersion := agentCoreVersion + "-SNAPSHOT"
	switch {
	case productionPackage && agentVersion.Major() >= 9:
		// for 9.0.0 and later versions, elastic-agent Helm chart is GA
		agentChartVersion = agentCoreVersion
	case productionPackage && agentVersion.Major() >= 8 && agentVersion.Minor() >= 18:
		// for 8.18.0 and later versions, elastic-agent Helm chart is GA
		agentChartVersion = agentCoreVersion
	}

	for yamlFile, keyVals := range map[string][]struct {
		key   string
		value string
	}{
		// values file for elastic-agent Helm Chart
		filepath.Join(helmChartPath, "values.yaml"): {
			{"agent.version", agentCoreVersion},
			// always use the SNAPSHOT version for image tag
			// for the chart that resides in the git repo
			{"agent.image.tag", agentImageTag},
		},
		// Chart.yaml for elastic-agent Helm Chart
		filepath.Join(helmChartPath, "Chart.yaml"): {
			{"appVersion", agentCoreVersion},
			{"version", agentChartVersion},
		},
	} {
		if err := updateYamlFile(yamlFile, keyVals...); err != nil {
			return fmt.Errorf("failed to update agent version: %w", err)
		}
	}

	// lint before packaging
	if err := h.Lint(); err != nil {
		return err
	}

	settings := cli.New() // Helm CLI settings
	actionConfig := &action.Configuration{}

	err := actionConfig.Init(settings.RESTClientGetter(), "default", "",
		func(format string, v ...interface{}) {})
	if err != nil {
		return fmt.Errorf("failed to init helm action config: %w", err)
	}

	packageAction := action.NewPackage()
	packagePath, err := packageAction.Run(helmChartPath, nil)
	if err != nil {
		return fmt.Errorf("failed to package helm chart: %w", err)
	}

	// Create a copy with the DRA naming convention
	// TODO: as soon as we confirm DRA works as expected we will replace the original naming
	alternativeName := fmt.Sprintf("elastic-agent-helm-chart-%s.tgz", agentChartVersion)

	srcFile := packagePath
	dstFile := filepath.Join(devtools.DistributionsDir, alternativeName)

	fmt.Printf(">>> CopyFile from %s to %s\n", srcFile, dstFile)
	devtools.CreateDir(dstFile)
	if err := copyFile(srcFile, dstFile); err != nil {
		return fmt.Errorf("failed to create alternative package name: %w", err)
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

func getMacOSMajorVersion() (int, error) {
	ver, err := sh.Output("sw_vers", "-productVersion")
	if err != nil {
		return 0, err
	}

	majorVerStr := strings.Split(ver, ".")[0]
	majorVer, err := strconv.Atoi(majorVerStr)
	if err != nil {
		return 0, fmt.Errorf("unable to parse major version from %q: %w", ver, err)
	}

	return majorVer, nil
}
