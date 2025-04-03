// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

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

// This is a helper function for flattenDependencies that's used when not packaging from a manifest
func ChecksumsWithoutManifest(versionedFlatPath string, versionedDropPath string, packageVersion string) map[string]string {
	globExpr := filepath.Join(versionedFlatPath, fmt.Sprintf("*%s*", packageVersion))
	if mg.Verbose() {
		log.Printf("Finding files to copy with %s", globExpr)
	}
	files, err := filepath.Glob(globExpr)
	if err != nil {
		panic(err)
	}
	if mg.Verbose() {
		log.Printf("Validating checksums for %+v", files)
		log.Printf("--- Copying into %s: %v", versionedDropPath, files)
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
			log.Printf("> prepare to copy %s into %s ", f, versionedDropPath)
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
		if mg.Verbose() {
			log.Printf(">>>> Looking to copy spec file: [%s]", specName)
		}

		checksum, err := CopyComponentSpecs(specName, versionedDropPath)
		if err != nil {
			panic(err)
		}

		checksums[specName+ComponentSpecFileSuffix] = checksum
	}

	return checksums
}

// This is a helper function for flattenDependencies that's used when building from a manifest
func ChecksumsWithManifest(platform, dependenciesVersion string, versionedFlatPath string, versionedDropPath string, manifestResponse *manifest.Build) map[string]string {
	checksums := make(map[string]string)
	if manifestResponse == nil {
		return checksums
	}

	// Iterate over the external binaries that we care about for packaging agent
	for _, spec := range packaging.ExpectedBinaries {

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

		// Combine the package name w/ the versioned flat path
		fullPath := filepath.Join(versionedFlatPath, manifestPackage.Name)

		// Eliminate the file extensions to get the proper directory
		// name that we need to copy
		var dirToCopy string
		if strings.HasSuffix(fullPath, ".tar.gz") {
			dirToCopy = fullPath[:strings.LastIndex(fullPath, ".tar.gz")]
		} else if strings.HasSuffix(fullPath, ".zip") {
			dirToCopy = fullPath[:strings.LastIndex(fullPath, ".zip")]
		} else {
			dirToCopy = fullPath
		}
		if mg.Verbose() {
			log.Printf(">>>>>>> Calculated directory to copy: [%s]", dirToCopy)
		}

		// Set copy options
		options := copy.Options{
			OnSymlink: func(_ string) copy.SymlinkAction {
				return copy.Shallow
			},
			Sync: true,
		}
		if mg.Verbose() {
			log.Printf("> prepare to copy %s into %s ", dirToCopy, versionedDropPath)
		}

		// Do the copy
		err = copy.Copy(dirToCopy, versionedDropPath, options)
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
