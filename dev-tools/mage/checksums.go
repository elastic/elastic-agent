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
func ChecksumsWithManifest(requiredPackage string, versionedFlatPath string, versionedDropPath string, manifestResponse *manifest.Build) map[string]string {
	checksums := make(map[string]string)
	if manifestResponse == nil {
		return checksums
	}

	// Iterate over the component projects in the manifest
	projects := manifestResponse.Projects
	for componentName := range projects {
		// Iterate over the individual package files within each component project
		for pkgName := range projects[componentName].Packages {
			// Only care about packages that match the required package constraint (os/arch)
			if strings.Contains(pkgName, requiredPackage) {
				// Iterate over the external binaries that we care about for packaging agent
				for _, spec := range manifest.ExpectedBinaries {
					// If the individual package doesn't match the expected prefix, then continue
					if !strings.HasPrefix(pkgName, spec.BinaryName) {
						continue
					}

					if mg.Verbose() {
						log.Printf(">>>>>>> Package [%s] matches requiredPackage [%s]", pkgName, requiredPackage)
					}

					// Get the version from the component based on the version in the package name
					// This is useful in the case where it's an Independent Agent Release, where
					// the opted-in projects will be one patch version ahead of the rest of the
					// opted-out/previously-released projects
					componentVersion := getComponentVersion(componentName, requiredPackage, projects[componentName])
					if mg.Verbose() {
						log.Printf(">>>>>>> Component [%s]/[%s] version is [%s]", componentName, requiredPackage, componentVersion)
					}

					// Combine the package name w/ the versioned flat path
					fullPath := filepath.Join(versionedFlatPath, pkgName)

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

<<<<<<< HEAD
					// cloud-defend path exception
					// When untarred, cloud defend untars to:
					//    cloud-defend-8.14.0-arm64
					// but the manifest (and most of this code) expects to be the same as
					// the name in the manifest, which is:
					//    cloud-defend-8.14.0-linux-x86_64
					// So we have to do a bit of a transformation here
					if strings.Contains(dirToCopy, "cloud-defend") {
						if strings.Contains(dirToCopy, "x86_64") {
							dirToCopy = fixCloudDefendDirPath(dirToCopy, componentVersion, "x86_64", "amd64")
						}
						if strings.Contains(dirToCopy, "arm64") {
							// Not actually replacing the arch, but removing the "linux"
							dirToCopy = fixCloudDefendDirPath(dirToCopy, componentVersion, "arm64", "arm64")
						}
						if mg.Verbose() {
							log.Printf(">>>>>>> Adjusted cloud-defend directory to copy: [%s]", dirToCopy)
						}
					}

=======
>>>>>>> 950e1d74ba (build(deps): bump github.com/elastic/elastic-agent-libs from 0.17.3 to 0.17.4 (#6237))
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
					err := copy.Copy(dirToCopy, versionedDropPath, options)
					if err != nil {
						panic(err)
					}

					// copy spec file for match
					specName := filepath.Base(dirToCopy)
					idx := strings.Index(specName, "-"+componentVersion)
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
			}
		}
	}

	return checksums
}

// This function is used when building with a Manifest.  In that manifest, it's possible
// for projects in an Independent Agent Release to have different versions since the opted-in
// ones will be one patch version higher than the opted-out/previously released projects.
// This function tries to find the versions from the package name
func getComponentVersion(componentName string, requiredPackage string, componentProject manifest.Project) string {
	var componentVersion string
	var foundIt bool
	// Iterate over all the packages in the component project
	for pkgName := range componentProject.Packages {
		// Only care about the external binaries that we want to package
		for _, spec := range manifest.ExpectedBinaries {
			// If the given component name doesn't match the external binary component, skip
			if componentName != spec.ProjectName {
				continue
			}

			// Split the package name on the binary name prefix plus a dash
			firstSplit := strings.Split(pkgName, spec.BinaryName+"-")
			if len(firstSplit) < 2 {
				continue
			}

			// Get the second part of the first split
			secondHalf := firstSplit[1]
			if len(secondHalf) < 2 {
				continue
			}

			// Make sure the second half matches the required package
			if strings.Contains(secondHalf, requiredPackage) {
				// ignore packages with names where this splitting doesn't results in proper version
				if strings.Contains(secondHalf, "docker-image") {
					continue
				}
				if strings.Contains(secondHalf, "oss-") {
					continue
				}

				// The component version should be the first entry after splitting w/ the requiredPackage
				componentVersion = strings.Split(secondHalf, "-"+requiredPackage)[0]
				foundIt = true
				// break out of inner loop
				break
			}
		}
		if foundIt {
			// break out of outer loop
			break
		}
	}

	if componentVersion == "" {
		errMsg := fmt.Sprintf("Unable to determine component version for [%s]", componentName)
		panic(errMsg)
	}

	return componentVersion
}
<<<<<<< HEAD

// This is a helper function for the cloud-defend package.
// When it is untarred, it does not have the same dirname as the package name.
// This adjusts for that and returns the actual path on disk for cloud-defend
func fixCloudDefendDirPath(dirPath string, componentVersion string, expectedArch string, actualArch string) string {
	fixedDirPath := dirPath

	cloudDefendExpectedDirName := fmt.Sprintf("cloud-defend-%s-linux-%s", componentVersion, expectedArch)
	cloudDefendActualDirName := fmt.Sprintf("cloud-defend-%s-%s", componentVersion, actualArch)
	if strings.Contains(fixedDirPath, cloudDefendExpectedDirName) {
		fixedDirPath = strings.ReplaceAll(fixedDirPath, cloudDefendExpectedDirName, cloudDefendActualDirName)
	}

	return fixedDirPath
}
=======
>>>>>>> 950e1d74ba (build(deps): bump github.com/elastic/elastic-agent-libs from 0.17.3 to 0.17.4 (#6237))
