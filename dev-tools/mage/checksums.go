// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/otiai10/copy"

	"github.com/elastic/elastic-agent/dev-tools/mage/manifest"
	"github.com/elastic/elastic-agent/dev-tools/packaging"
)

const ComponentSpecFileSuffix = ".spec.yml"

func CopyComponentSpecs(componentName, versionedDropPath string) (string, error) {
	specFileName := componentName + ComponentSpecFileSuffix
	targetPath := filepath.Join(versionedDropPath, specFileName)

	if _, err := os.Stat(targetPath); err != nil {
		fmt.Printf(">> File %s does not exist, reverting to local specfile\n", targetPath)
		// spec not present copy from local
		sourceSpecFile := filepath.Join("specs", specFileName)
		if mg.Verbose() {
			log.Printf("Copy spec from %s to %s", sourceSpecFile, targetPath)
		}
		err := Copy(sourceSpecFile, targetPath)
		if err != nil {
			return "", fmt.Errorf("failed copying spec file %q to %q: %w", sourceSpecFile, targetPath, err)
		}
	}

	// compute checksum
	return GetSHA512Hash(targetPath)
}

// ChecksumsWithoutManifest is a helper function for flattenDependencies that's used when not packaging from a manifest.
// This function will iterate over the dependencies, resolve *exactly* the package name for each dependency and platform using the passed
// dependenciesVersion, and it will copy the extracted files contained in the rootDir of each dependency from the versionedFlatPath
// (a directory containing all the extracted dependencies per platform) to the versionedDropPath (a drop path by platform
// that will be used to compose the package content)
// ChecksumsWithoutManifest will accumulate the checksums of each component spec that is copied, and return it to the caller.
func ChecksumsWithoutManifest(platform string, dependenciesVersion string, versionedFlatPath string, versionedDropPath string, dependencies []packaging.BinarySpec) map[string]string {
	checksums := make(map[string]string)

	for _, dep := range dependencies {

		if dep.PythonWheel {
			if mg.Verbose() {
				log.Printf(">>>>>>> Component %s/%s is a Python wheel, skipping", dep.ProjectName, dep.BinaryName)
			}
			continue
		}

		if !dep.SupportsPlatform(platform) {
			log.Printf(">>>>>>> Component %s/%s does not support platform %s, skipping", dep.ProjectName, dep.BinaryName, platform)
			continue
		}

		srcDir := filepath.Join(versionedFlatPath, dep.GetRootDir(dependenciesVersion, platform))

		if mg.Verbose() {
			log.Printf("Validating checksums for %+v", dep.BinaryName)
			log.Printf("--- Copying into %s: %v", versionedDropPath, srcDir)
		}

		options := copy.Options{
			OnSymlink: func(_ string) copy.SymlinkAction {
				return copy.Shallow
			},
			Sync: true,
		}
		if mg.Verbose() {
			log.Printf("> prepare to copy %s into %s ", srcDir, versionedDropPath)
		}

		err := copy.Copy(srcDir, versionedDropPath, options)
		if err != nil {
			panic(fmt.Errorf("copying dependency %s files from %q to %q: %w", dep.BinaryName, srcDir, versionedDropPath, err))
		}

		// copy spec file for match
		if mg.Verbose() {
			log.Printf(">>>> Looking to copy spec file: [%s]", dep.BinaryName)
		}

		checksum, err := CopyComponentSpecs(dep.BinaryName, versionedDropPath)
		if err != nil {
			panic(err)
		}

		checksums[dep.BinaryName+ComponentSpecFileSuffix] = checksum
	}

	return checksums
}

// ChecksumsWithManifest is a helper function for flattenDependencies that's used when building from a manifest.
// This function will iterate over the dependencies, resolve the package name for each dependency and platform using the manifest,
// (there may be some variability there in case the manifest does not include an exact match for the expected filename),
// and it will copy the extracted files contained in the rootDir of each dependency from the versionedFlatPath
// (a directory containing all the extracted dependencies per platform) to the versionedDropPath (a drop path by platform
// that will be used to compose the package content)
// ChecksumsWithManifest will accumulate the checksums of each component spec that is copied, and return it to the caller.
func ChecksumsWithManifest(platform string, dependenciesVersion string, versionedFlatPath string, versionedDropPath string, manifestResponse *manifest.Build, dependencies []packaging.BinarySpec) map[string]string {
	checksums := make(map[string]string)
	if manifestResponse == nil {
		return checksums
	}

	// Iterate over the external binaries that we care about for packaging agent
	for _, spec := range dependencies {

		if spec.PythonWheel {
			if mg.Verbose() {
				log.Printf(">>>>>>> Component %s/%s is a Python wheel, skipping", spec.ProjectName, spec.BinaryName)
			}
			continue
		}

		if !spec.SupportsPlatform(platform) {
			log.Printf(">>>>>>> Component %s/%s does not support platform %s, skipping", spec.ProjectName, spec.BinaryName, platform)
			continue
		}

		manifestPackage, err := manifest.ResolveManifestPackage(manifestResponse.Projects[spec.ProjectName], spec, dependenciesVersion, platform)
		if err != nil {
			if mg.Verbose() {
				log.Printf(">>>>>>> Error resolving package for [%s/%s]", spec.BinaryName, platform)
			}
			continue
		}

		rootDir := spec.GetRootDir(manifestPackage.ActualVersion, platform)

		// Combine the package name w/ the versioned flat path
		fullPath := filepath.Join(versionedFlatPath, rootDir)

		if mg.Verbose() {
			log.Printf(">>>>>>> Calculated directory to copy: [%s]", fullPath)
		}

		// Set copy options
		options := copy.Options{
			OnSymlink: func(_ string) copy.SymlinkAction {
				return copy.Shallow
			},
			Sync: true,
		}
		if mg.Verbose() {
			log.Printf("> prepare to copy %s into %s ", fullPath, versionedDropPath)
		}

		// Do the copy
		err = copy.Copy(fullPath, versionedDropPath, options)
		if err != nil {
			panic(err)
		}

		checksum, err := CopyComponentSpecs(spec.BinaryName, versionedDropPath)
		if err != nil {
			panic(err)
		}

		checksums[spec.BinaryName+ComponentSpecFileSuffix] = checksum
	}

	return checksums
}
