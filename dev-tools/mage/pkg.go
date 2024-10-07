// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Package packages the Beat for distribution. It generates packages based on
// the set of target platforms and registered packaging specifications.
func Package() error {
	fmt.Println("--- Package artifact")
	if len(Platforms) == 0 {
		fmt.Println(">> package: Skipping because the platform list is empty")
		return nil
	}

	if len(Packages) == 0 {
		return fmt.Errorf("no package specs are registered. Call " +
			"UseCommunityBeatPackaging, UseElasticBeatPackaging or USeElasticBeatWithoutXPackPackaging first")
	}

	// platforms := updateWithDarwinUniversal(Platforms)
	platforms := Platforms

	tasks := make(map[string][]interface{})
	for _, target := range platforms {
		for _, pkg := range Packages {
			if pkg.OS != target.GOOS() || pkg.Arch != "" && pkg.Arch != target.Arch() {
				continue
			}

			for _, pkgType := range pkg.Types {
				if !isPackageTypeSelected(pkgType) {
					log.Printf("Skipping %s package type because it is not selected", pkgType)
					continue
				}

				if pkgType == Docker && !isDockerVariantSelected(pkg.Spec.DockerVariant) {
					log.Printf("Skipping %s docker variant type because it is not selected", pkg.Spec.DockerVariant)
					continue
				}

				if target.Name == "linux/arm64" && pkgType == Docker && runtime.GOARCH != "arm64" {
					log.Printf("Skipping Docker package type because build host isn't arm")
					continue
				}

				packageArch, err := getOSArchName(target, pkgType)
				if err != nil {
					log.Printf("Skipping arch %v for package type %v: %v", target.Arch(), pkgType, err)
					continue
				}

				agentPackageType := TarGz
				if pkg.OS == "windows" {
					agentPackageType = Zip
				}

				agentPackageArch, err := getOSArchName(target, agentPackageType)
				if err != nil {
					log.Printf("Skipping arch %v for package type %v: %v", target.Arch(), pkgType, err)
					continue
				}

				agentPackageDrop, _ := os.LookupEnv("AGENT_DROP_PATH")

				spec := pkg.Spec.Clone()
				spec.OS = target.GOOS()
				spec.Arch = packageArch
				spec.Snapshot = Snapshot
				spec.evalContext = map[string]interface{}{
					"GOOS":          target.GOOS(),
					"GOARCH":        target.GOARCH(),
					"GOARM":         target.GOARM(),
					"Platform":      target,
					"AgentArchName": agentPackageArch,
					"PackageType":   pkgType.String(),
					"BinaryExt":     binaryExtension(target.GOOS()),
					"AgentDropPath": agentPackageDrop,
				}

				spec.packageDir, err = pkgType.PackagingDir(packageStagingDir, target, spec)
				if err != nil {
					log.Printf("Skipping arch %v for package type %v: %v", target.Arch(), pkgType, err)
					continue
				}

				spec = spec.Evaluate()

				tasks[target.GOOS()+"-"+target.Arch()] = append(tasks[target.GOOS()+"-"+target.Arch()], packageBuilder{target, spec, pkgType}.Build)
			}
		}
	}

	for k, v := range tasks {
		fmt.Printf(">> package: Building %s\n", k)
		Parallel(v...)
	}
	return nil
}

// isPackageTypeSelected returns true if SelectedPackageTypes is empty or if
// pkgType is present on SelectedPackageTypes. It returns false otherwise.
func isPackageTypeSelected(pkgType PackageType) bool {
	if len(SelectedPackageTypes) == 0 {
		return true
	}

	for _, t := range SelectedPackageTypes {
		if t == pkgType {
			return true
		}
	}
	return false
}

// isDockerVariantSelected returns true if SelectedDockerVariants is empty or if
// docVariant is present on SelectedDockerVariants. It returns false otherwise.
func isDockerVariantSelected(docVariant DockerVariant) bool {
	if len(SelectedDockerVariants) == 0 {
		return true
	}

	for _, v := range SelectedDockerVariants {
		if v == docVariant {
			return true
		}
	}
	return false
}

type packageBuilder struct {
	Platform BuildPlatform
	Spec     PackageSpec
	Type     PackageType
}

func (b packageBuilder) Build() error {
	fmt.Printf(">> package: Building %v type=%v for platform=%v\n", b.Spec.Name, b.Type, b.Platform.Name)
	log.Printf("Package spec: %+v", b.Spec)
	if err := b.Type.Build(b.Spec); err != nil {
		return fmt.Errorf("failed building %v type=%v for platform=%v : %w",
			b.Spec.Name, b.Type, b.Platform.Name, err)
	}
	return nil
}

type testPackagesParams struct {
	HasModules           bool
	HasMonitorsD         bool
	HasModulesD          bool
	HasRootUserContainer bool
	MinModules           *int
}

// TestPackagesOption defines a option to the TestPackages target.
type TestPackagesOption func(params *testPackagesParams)

// WithModules enables modules folder contents testing
func WithModules() func(params *testPackagesParams) {
	return func(params *testPackagesParams) {
		params.HasModules = true
	}
}

// MinModules sets the minimum number of modules to require
func MinModules(n int) func(params *testPackagesParams) {
	return func(params *testPackagesParams) {
		minModules := n
		params.MinModules = &minModules
	}
}

// WithMonitorsD enables monitors folder contents testing.
func WithMonitorsD() func(params *testPackagesParams) {
	return func(params *testPackagesParams) {
		params.HasMonitorsD = true
	}
}

// WithModulesD enables modules.d folder contents testing
func WithModulesD() func(params *testPackagesParams) {
	return func(params *testPackagesParams) {
		params.HasModulesD = true
	}
}

// WithRootUserContainer allows root when checking user in container
func WithRootUserContainer() func(params *testPackagesParams) {
	return func(params *testPackagesParams) {
		params.HasRootUserContainer = true
	}
}

// TestPackages executes the package tests on the produced binaries. These tests
// inspect things like file ownership and mode.
func TestPackages(options ...TestPackagesOption) error {
	fmt.Println("--- TestPackages")
	params := testPackagesParams{}
	for _, opt := range options {
		opt(&params)
	}

	fmt.Println(">> Testing package contents")
	goTest := sh.OutCmd("go", "test")

	var args []string
	if mg.Verbose() {
		args = append(args, "-v")
	}

	args = append(args, MustExpand("{{ elastic_beats_dir }}/dev-tools/packaging/package_test.go"))

	if params.HasModules {
		args = append(args, "--modules")
	}

	if params.MinModules != nil {
		args = append(args, "--min-modules", strconv.Itoa(*params.MinModules))
	}

	if params.HasMonitorsD {
		args = append(args, "--monitors.d")
	}

	if params.HasModulesD {
		args = append(args, "--modules.d")
	}

	if params.HasRootUserContainer {
		args = append(args, "--root-user-container")
	}

	if BeatUser == "root" {
		args = append(args, "-root-owner")
	}

	args = append(args, "-files", MustExpand("{{.PWD}}/build/distributions/*"))

	if out, err := goTest(args...); err != nil {
		if mg.Verbose() {
			fmt.Println(out)
		}
		return fmt.Errorf("error running package_test.go: %w, stdout: %s", err, out)
	}

	return nil
}

// TestLinuxForCentosGLIBC checks the GLIBC requirements of linux/amd64 and
// linux/386 binaries to ensure they meet the requirements for RHEL 6 which has
// glibc 2.12.
func TestLinuxForCentosGLIBC() error {
	switch Platform.Name {
	case "linux/amd64", "linux/386":
		return TestBinaryGLIBCVersion(filepath.Join("build/golang-crossbuild", BeatName+"-linux-"+Platform.GOARCH), "2.12")
	default:
		return nil
	}
}

// TestBinaryGLIBCVersion checks GLIBC requirements
func TestBinaryGLIBCVersion(elfPath, maxGlibcVersion string) error {
	requiredGlibc, err := ReadGLIBCRequirement(elfPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	upperBound, err := NewSemanticVersion(maxGlibcVersion)
	if err != nil {
		return err
	}

	if !requiredGlibc.LessThanOrEqual(upperBound) {
		return fmt.Errorf("dynamically linked binary %q requires glibc "+
			"%v, but maximum allowed glibc is %v",
			elfPath, requiredGlibc, upperBound)
	}
	fmt.Printf(">> testBinaryGLIBCVersion: %q requires glibc %v or greater\n", elfPath, requiredGlibc)
	return nil
}
