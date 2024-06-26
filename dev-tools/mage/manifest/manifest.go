// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package manifest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/magefile/mage/mg"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/version"
)

// A backoff schedule for when and how often to retry failed HTTP
// requests. The first element is the time to wait after the
// first failure, the second the time to wait after the second
// failure, etc. After reaching the last element, retries stop
// and the request is considered failed.
var backoffSchedule = []time.Duration{
	1 * time.Second,
	3 * time.Second,
	10 * time.Second,
}

var errorInvalidManifestURL = errors.New("invalid ManifestURL provided")
var errorNotAllowedManifestURL = errors.New("the provided ManifestURL is not allowed URL")

var AllowedManifestHosts = []string{"snapshots.elastic.co", "staging.elastic.co"}

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
var ExternalBinaries = map[string]string{
	"agentbeat":             "beats",
	"apm-server":            "apm-server", // not supported on darwin/aarch64
	"cloudbeat":             "cloudbeat",  // only supporting linux/amd64 or linux/arm64
	"cloud-defend":          "cloud-defend",
	"endpoint-security":     "endpoint-dev",
	"fleet-server":          "fleet-server",
	"pf-elastic-collector":  "prodfiler",
	"pf-elastic-symbolizer": "prodfiler",
	"pf-host-agent":         "prodfiler",
}

// Converts ExternalBinaries into a map of projects and the packages they contain. For example:
// "prodfiler": {"pf-elastic-collector", "pf-elastic-symbolizer", "pf-host-agent"}
func expectedProjectPkgs() map[string][]string {
	expectedProjectPkgs := make(map[string][]string)
	for component, pkg := range ExternalBinaries {
		expectedProjectPkgs[pkg] = append(expectedProjectPkgs[pkg], component)
	}
	return expectedProjectPkgs
}

// DownloadManifest is going to download the given manifest file and return the ManifestResponse
func DownloadManifest(ctx context.Context, manifest string) (tools.Build, error) {
	manifestUrl, urlError := url.Parse(manifest)
	if urlError != nil {
		return tools.Build{}, errorInvalidManifestURL
	}
	var valid = false
	for _, manifestHost := range AllowedManifestHosts {
		if manifestHost == manifestUrl.Host {
			valid = true
		}
	}
	if !valid {
		log.Printf("Not allowed %s, valid ones are %+v", manifestUrl.Host, AllowedManifestHosts)
		return tools.Build{}, errorNotAllowedManifestURL
	}
	sanitizedUrl := fmt.Sprintf("https://%s%s", manifestUrl.Host, manifestUrl.Path)
	f := func() (tools.Build, error) { return downloadManifestData(ctx, sanitizedUrl) }
	manifestResponse, err := doWithRetries(f)
	if err != nil {
		return tools.Build{}, fmt.Errorf("downloading manifest: %w", err)
	}
	if mg.Verbose() {
		log.Printf(">>>> Downloaded manifest %s", manifest)
		log.Printf(">>>> Packaging version: %s, build_id: %s, manifest_version:%s", manifestResponse.Version, manifestResponse.BuildID, manifestResponse.ManifestVersion)
	}
	return manifestResponse, nil
}

func resolveManifestPackage(project tools.Project, pkg string, reqPackage string, version string) ([]string, error) {
	var val tools.Package
	var ok bool

	// Try the normal/easy case first
	packageName := fmt.Sprintf("%s-%s-%s", pkg, version, reqPackage)
	val, ok = project.Packages[packageName]
	if !ok {
		// If we didn't find it, it may be an Independent Agent Release, where
		// the opted-in projects will have a patch version one higher than
		// the rest of the projects, so we need to seek that out
		if mg.Verbose() {
			log.Printf(">>>>>>>>>>> Looking for package [%s] of type [%s]", pkg, reqPackage)
		}

		var foundIt bool
		for pkgName := range project.Packages {
			if strings.HasPrefix(pkgName, pkg) {
				firstSplit := strings.Split(pkgName, pkg+"-")
				if len(firstSplit) < 2 {
					continue
				}

				secondHalf := firstSplit[1]
				// Make sure we're finding one w/ the same required package type
				if strings.Contains(secondHalf, reqPackage) {

					// Split again after the version with the required package string
					secondSplit := strings.Split(secondHalf, "-"+reqPackage)
					if len(secondSplit) < 2 {
						continue
					}

					// The first element after the split should normally be the version
					pkgVersion := secondSplit[0]
					if mg.Verbose() {
						log.Printf(">>>>>>>>>>> Using derived version for package [%s]: %s ", pkgName, pkgVersion)
					}

					// Create a project/package key with the package, derived version, and required package
					foundPkgKey := fmt.Sprintf("%s-%s-%s", pkg, pkgVersion, reqPackage)
					if mg.Verbose() {
						log.Printf(">>>>>>>>>>> Looking for project package key: [%s]", foundPkgKey)
					}

					// Get the package value, if it exists
					val, ok = project.Packages[foundPkgKey]
					if !ok {
						continue
					}

					if mg.Verbose() {
						log.Printf(">>>>>>>>>>> Found package key [%s]", foundPkgKey)
					}

					foundIt = true
				}
			}
		}

		if !foundIt {
			return nil, fmt.Errorf("package [%s] not found in project manifest at %s", packageName, project.ExternalArtifactsManifestURL)
		}
	}

	if mg.Verbose() {
		log.Printf(">>>>>>>>>>> Project branch/commit [%s, %s]", project.Branch, project.CommitHash)
	}

	return []string{val.URL, val.ShaURL, val.AscURL}, nil
}

// DownloadComponentsFromManifest is going to download a set of components from the given manifest into the destination
// dropPath folder in order to later use that folder for packaging
func DownloadComponentsFromManifest(ctx context.Context, manifest string, platforms []string, platformPackages map[string]string, dropPath string) error {
	manifestResponse, err := DownloadManifest(ctx, manifest)
	if err != nil {
		return fmt.Errorf("failed to download remote manifest file %w", err)
	}
	projects := manifestResponse.Projects

	parsedManifestVersion, err := version.ParseVersion(manifestResponse.Version)
	if err != nil {
		return fmt.Errorf("failed to parse manifest version: [%s]", manifestResponse.Version)
	}

	// For resolving manifest package name and version, just use the Major.Minor.Patch part of the version
	// for Staging builds, and Major.Minor.Patch-SNAPSHOT for snapshots.
	// This eliminates the "+buildYYYYMMDDHHMM" suffix on Independent Agent Release builds
	majorMinorPatchVersion := parsedManifestVersion.VersionWithPrerelease()

	errGrp, downloadsCtx := errgroup.WithContext(ctx)
	for project, pkgs := range expectedProjectPkgs() {
		for _, platform := range platforms {
			targetPath := filepath.Join(dropPath)
			err := os.MkdirAll(targetPath, 0755)
			if err != nil {
				return fmt.Errorf("failed to create directory %s", targetPath)
			}
			log.Printf("+++ Prepare to download project [%s] for [%s]", project, platform)

			for _, pkg := range pkgs {
				reqPackage := platformPackages[platform]
				pkgURL, err := resolveManifestPackage(projects[project], pkg, reqPackage, majorMinorPatchVersion)
				if err != nil {
					return err
				}

				for _, p := range pkgURL {
					log.Printf(">>>>>>>>> Downloading [%s] [%s] ", pkg, p)
					pkgFilename := path.Base(p)
					downloadTarget := filepath.Join(targetPath, pkgFilename)
					if _, err := os.Stat(downloadTarget); err != nil {
						errGrp.Go(func(ctx context.Context, url, target string) func() error {
							return func() error { return DownloadPackage(ctx, url, target) }
						}(downloadsCtx, p, downloadTarget))
					}
				}
			}
		}
	}

	err = errGrp.Wait()
	if err != nil {
		return fmt.Errorf("error downloading files: %w", err)
	}

	log.Printf("Downloads for manifest %q complete.", manifest)
	return nil
}

func DownloadPackage(ctx context.Context, downloadUrl string, target string) error {
	parsedURL, errorUrl := url.Parse(downloadUrl)
	if errorUrl != nil {
		return errorInvalidManifestURL
	}
	var valid = false
	for _, manifestHost := range AllowedManifestHosts {
		if manifestHost == parsedURL.Host {
			valid = true
		}
	}
	if !valid {
		log.Printf("Not allowed %s, valid ones are %+v", parsedURL.Host, AllowedManifestHosts)
		return errorNotAllowedManifestURL
	}
	cleanUrl := fmt.Sprintf("https://%s%s", parsedURL.Host, parsedURL.Path)
	_, err := doWithRetries(func() (string, error) { return downloadFile(ctx, cleanUrl, target) })
	return err
}
