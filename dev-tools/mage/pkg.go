// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"fmt"
	"log"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Package packages the Beat for distribution using the provided config and package specifications.
// It generates packages based on the set of target platforms and the given packaging specifications.
func Package(ctx context.Context, cfg *Settings, packages []OSPackageArgs) error {
	fmt.Println("--- Package artifact")
	platforms := cfg.GetPlatforms()
	if len(platforms) == 0 {
		fmt.Println(">> package: Skipping because the platform list is empty")
		return nil
	}

	if len(packages) == 0 {
		return fmt.Errorf("no package specs provided. Use " +
			"LoadElasticAgentPackageSpec or LoadElasticAgentCorePackageSpec to load them")
	}

	if mg.Verbose() {
		debugSelectedPackageSpecsWithPlatform := make([]string, 0, len(packages))
		for _, p := range packages {
			debugSelectedPackageSpecsWithPlatform = append(debugSelectedPackageSpecsWithPlatform, fmt.Sprintf("spec %s on %s/%s", p.Spec.Name, p.OS, p.Arch))
		}

		log.Printf("Packaging for platforms %v, packages %v", platforms, debugSelectedPackageSpecsWithPlatform)
	}

	tasks := make(map[string][]interface{})
	for _, target := range platforms {
		for _, pkg := range packages {
			if pkg.OS != target.GOOS() || pkg.Arch != "" && pkg.Arch != target.Arch() {
				continue
			}

			// Checks if this package is compatible with the FIPS settings
			if pkg.Spec.FIPS != cfg.Build.FIPSBuild {
				log.Printf("Skipping %s/%s package type because FIPS flag doesn't match [pkg=%v, build=%v]", pkg.Spec.Name, pkg.OS, pkg.Spec.FIPS, cfg.Build.FIPSBuild)
				continue
			}

			for _, pkgType := range pkg.Types {
				if !cfg.IsPackageTypeSelected(pkgType) {
					log.Printf("Skipping %s package type because it is not selected", pkgType)
					continue
				}

				if pkgType == Docker && !cfg.IsDockerVariantSelected(pkg.Spec.DockerVariant) {
					log.Printf("Skipping %s docker variant type because it is not selected", pkg.Spec.DockerVariant)
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

				agentPackageDrop := cfg.Packaging.AgentDropPath

				spec := pkg.Spec.Clone()
				spec.cfg = cfg
				spec.OS = target.GOOS()
				spec.Arch = packageArch
				spec.Snapshot = cfg.Build.Snapshot
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

				if mg.Verbose() {
					log.Printf("Adding task for packaging %s on %s/%s", spec.Name, target.GOOS(), target.Arch())
				}

				tasks[target.GOOS()+"-"+target.Arch()] = append(tasks[target.GOOS()+"-"+target.Arch()], packageBuilder{target, spec, pkgType}.Build)
			}
		}
	}

	for k, v := range tasks {
		fmt.Printf(">> package: Building %s\n", k)
		ParallelCtx(ctx, v...)
	}
	return nil
}

type packageBuilder struct {
	Platform BuildPlatform
	Spec     PackageSpec
	Type     PackageType
}

func (b packageBuilder) Build(ctx context.Context) error {
	fmt.Printf(">> package: Building %v type=%v for platform=%v fips=%v\n", b.Spec.Name, b.Type, b.Platform.Name, b.Spec.FIPS)
	log.Printf("Package spec: %+v", b.Spec)
	if err := b.Type.Build(ctx, b.Spec); err != nil {
		return fmt.Errorf("failed building %v type=%v for platform=%v fips=%v : %w",
			b.Spec.Name, b.Type, b.Platform.Name, b.Spec.FIPS, err)
	}
	return nil
}

// TestPackages executes the package tests on the produced binaries. These tests
// inspect things like file ownership and mode.
func TestPackages(cfg *Settings) error {
	fmt.Println("--- TestPackages")
	fmt.Println(">> Testing package contents")
	goTest := sh.OutCmd("go", "test")

	var args []string
	args = append(args, "--timeout", "30m")
	if mg.Verbose() {
		args = append(args, "-v")
	}

	args = append(args, MustExpand(cfg, "{{ elastic_beats_dir }}/dev-tools/packaging/testing/package_test.go"))

	if cfg.Beat.User == "root" {
		args = append(args, "-root-owner")
	}

	args = append(args, "-files", MustExpand(cfg, "{{.PWD}}/build/distributions/*"))
	args = append(args, "--source-root", MustExpand(cfg, "{{.PWD}}"))

	if out, err := goTest(args...); err != nil {
		if mg.Verbose() {
			fmt.Println(out)
		}
		return fmt.Errorf("error running package_test.go: %w, stdout: %s", err, out)
	}

	return nil
}
