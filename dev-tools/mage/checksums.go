// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"io"
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

// componentMetadataFiles are files that several components ship under the same name. They are renamed to
// <stem>.<component><ext> (e.g. NOTICE.apm-server.txt) when merged into the shared drop path, so that
// the files of every component end up in the package instead of only the last copied one.
var componentMetadataFiles = map[string]bool{
	"NOTICE.txt":      true,
	"LICENSE.txt":     true,
	".build_hash.txt": true,
}

// componentDestination returns the path a component file is copied to in the drop path: metadata files
// get the component name added, everything else keeps its name.
func componentDestination(dest, component string) string {
	dir, base := filepath.Split(dest)
	if !componentMetadataFiles[base] {
		return dest
	}
	ext := filepath.Ext(base)
	return filepath.Join(dir, strings.TrimSuffix(base, ext)+"."+component+ext)
}

// componentCopyOptions returns the copy options used to merge the root dir of a component into the
// shared drop path. Metadata files are renamed per component (see componentMetadataFiles). When a
// component overwrites any other file that already exists in the drop path, a warning is written to
// warnOut, because only the last copy ends up in the package. The warning is not sent through the log
// package: mage discards it unless running with -v.
func componentCopyOptions(component string, warnOut io.Writer) copy.Options {
	return copy.Options{
		OnSymlink: func(_ string) copy.SymlinkAction {
			return copy.Shallow
		},
		Sync: true,
		// Skip is called with the original destination, before RenameDestination: check the path
		// that is actually going to be written.
		Skip: func(info os.FileInfo, _, dest string) (bool, error) {
			// directories are merged, only files can be overwritten
			if info.IsDir() {
				return false, nil
			}
			dest = componentDestination(dest, component)
			// Lstat, as the destination can be a symlink copied shallowly from another component
			if _, err := os.Lstat(dest); err == nil {
				fmt.Fprintf(warnOut, "WARNING: component %s overwrites existing file %s\n", component, dest)
			}
			return false, nil
		},
		RenameDestination: func(_, dest string) (string, error) {
			return componentDestination(dest, component), nil
		},
	}
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

		if mg.Verbose() {
			log.Printf("> prepare to copy %s into %s ", srcDir, versionedDropPath)
		}

		err := copy.Copy(srcDir, versionedDropPath, componentCopyOptions(dep.BinaryName, os.Stderr))
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

		if mg.Verbose() {
			log.Printf("> prepare to copy %s into %s ", fullPath, versionedDropPath)
		}

		// Do the copy
		err = copy.Copy(fullPath, versionedDropPath, componentCopyOptions(spec.BinaryName, os.Stderr))
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
