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

	"github.com/elastic/elastic-agent/dev-tools/mage/target/common"
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

// Map of binaries to download to their project in the unified-release manager.
// The project names are those used in the "projects" list in the unified release manifest.
// See the sample manifests in the testdata directory.
var ExpectedBinaries = map[string]Project{
	"agentbeat":             Project{Name: "beats", Platforms: AllPlatforms},
	"apm-server":            Project{Name: "apm-server", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}, {"windows", "x86_64"}, {"darwin", "x86_64"}}},
	"cloudbeat":             Project{Name: "cloudbeat", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}},
	"cloud-defend":          Project{Name: "cloud-defend", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}},
	"endpoint-security":     Project{Name: "endpoint-dev", Platforms: AllPlatforms},
	"fleet-server":          Project{Name: "fleet-server", Platforms: AllPlatforms},
	"pf-elastic-collector":  Project{Name: "prodfiler", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}},
	"pf-elastic-symbolizer": Project{Name: "prodfiler", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}},
	"pf-host-agent":         Project{Name: "prodfiler", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}},
}

type Project struct {
	Name      string
	Platforms []Platform
}

func (proj Project) SupportsPlatform(platform string) bool {
	for _, p := range proj.Platforms {
		if p.Platform() == platform {
			return true
		}
	}
	return false
}

type Platform struct {
	OS   string
	Arch string
}

// Converts to the format expected on the mage command line "linux", "x86_64" = "linux/amd64"
func (p Platform) Platform() string {
	if p.Arch == "x86_64" {
		p.Arch = "amd64"
	}
	if p.Arch == "aarch64" {
		p.Arch = "arm64"
	}
	return p.OS + "/" + p.Arch
}

var AllPlatforms = []Platform{{"linux", "x86_64"}, {"linux", "arm64"}, {"windows", "x86_64"}, {"darwin", "x86_64"}, {"darwin", "aarch64"}}

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

// DownloadComponentsFromManifest is going to download a set of components from the given manifest into the destination
// dropPath folder in order to later use that folder for packaging
func DownloadComponentsFromManifest(ctx context.Context, manifest string, platforms []string, dropPath string) error {
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
	// for project, pkgs := range expectedProjectPkgs() {
	for binary, project := range ExpectedBinaries {
		for _, platform := range platforms {
			targetPath := filepath.Join(dropPath)
			err := os.MkdirAll(targetPath, 0755)
			if err != nil {
				return fmt.Errorf("failed to create directory %s", targetPath)
			}
			log.Printf("+++ Prepare to download project [%s] for [%s]", project.Name, platform)

			if !project.SupportsPlatform(platform) {
				log.Printf(">>>>>>>>> Project [%s] does not support platform [%s] ", binary, platform)
				continue
			}

			pkgURL, err := resolveManifestPackage(projects[project.Name], binary, common.PlatformPackages[platform], majorMinorPatchVersion)
			if err != nil {
				return err
			}

			for _, p := range pkgURL {
				log.Printf(">>>>>>>>> Downloading [%s] [%s] ", binary, p)
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

	err = errGrp.Wait()
	if err != nil {
		return fmt.Errorf("error downloading files: %w", err)
	}

	log.Printf("Downloads for manifest %q complete.", manifest)
	return nil
}

func resolveManifestPackage(project tools.Project, binary string, platformPkg string, version string) ([]string, error) {
	var val tools.Package
	var ok bool

	// Try the normal/easy case first
	packageName := fmt.Sprintf("%s-%s-%s", binary, version, platformPkg)
	val, ok = project.Packages[packageName]
	if !ok {
		// If we didn't find it, it may be an Independent Agent Release, where
		// the opted-in projects will have a patch version one higher than
		// the rest of the projects, so we need to seek that out
		if mg.Verbose() {
			log.Printf(">>>>>>>>>>> Looking for package [%s] of type [%s]", binary, platformPkg)
		}

		var foundIt bool
		for pkgName := range project.Packages {
			if strings.HasPrefix(pkgName, binary) {
				firstSplit := strings.Split(pkgName, binary+"-")
				if len(firstSplit) < 2 {
					continue
				}

				secondHalf := firstSplit[1]
				// Make sure we're finding one w/ the same required package type
				if strings.Contains(secondHalf, platformPkg) {

					// Split again after the version with the required package string
					secondSplit := strings.Split(secondHalf, "-"+platformPkg)
					if len(secondSplit) < 2 {
						continue
					}

					// The first element after the split should normally be the version
					pkgVersion := secondSplit[0]
					if mg.Verbose() {
						log.Printf(">>>>>>>>>>> Using derived version for package [%s]: %s ", pkgName, pkgVersion)
					}

					// Create a project/package key with the package, derived version, and required package
					foundPkgKey := fmt.Sprintf("%s-%s-%s", binary, pkgVersion, platformPkg)
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
