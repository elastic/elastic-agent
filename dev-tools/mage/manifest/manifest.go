// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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

	"github.com/elastic/elastic-agent/dev-tools/mage/pkgcommon"
	"github.com/elastic/elastic-agent/pkg/version"
)

type Build struct {
	Projects             map[string]Project `json:"projects"`
	StartTime            string             `json:"start_time"`
	ReleaseBranch        string             `json:"release_branch"`
	Prefix               string             `json:"prefix"`
	EndTime              string             `json:"end_time"`
	ManifestVersion      string             `json:"manifest_version"`
	Version              string             `json:"version"`
	Branch               string             `json:"branch"`
	BuildID              string             `json:"build_id"`
	BuildDurationSeconds int                `json:"build_duration_seconds"`
}
type Project struct {
	Branch                       string             `json:"branch"`
	CommitHash                   string             `json:"commit_hash"`
	CommitURL                    string             `json:"commit_url"`
	ExternalArtifactsManifestURL string             `json:"external_artifacts_manifest_url"`
	BuildDurationSeconds         int                `json:"build_duration_seconds"`
	Packages                     map[string]Package `json:"packages"`
	Dependencies                 []Dependency       `json:"dependencies"`
}

type Package struct {
	URL          string   `json:"url"`
	ShaURL       string   `json:"sha_url"`
	AscURL       string   `json:"asc_url"`
	Type         string   `json:"type"`
	Architecture string   `json:"architecture"`
	Os           []string `json:"os"`
	Classifier   string   `json:"classifier"`
	Attributes   struct {
		IncludeInRepo string `json:"include_in_repo"`
		ArtifactNoKpi string `json:"artifactNoKpi"`
		Internal      string `json:"internal"`
		ArtifactID    string `json:"artifact_id"`
		Oss           string `json:"oss"`
		Group         string `json:"group"`
	} `json:"attributes"`
}

type Dependency struct {
	Prefix   string `json:"prefix"`
	BuildUri string `json:"build_uri"`
}

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

var (
	errorInvalidManifestURL    = errors.New("invalid ManifestURL provided")
	errorNotAllowedManifestURL = errors.New("the provided ManifestURL is not allowed URL")
)

var AllowedManifestHosts = []string{"snapshots.elastic.co", "staging.elastic.co"}

var PlatformPackages = map[string]string{
	"darwin/amd64":  "darwin-x86_64.tar.gz",
	"darwin/arm64":  "darwin-aarch64.tar.gz",
	"linux/amd64":   "linux-x86_64.tar.gz",
	"linux/arm64":   "linux-arm64.tar.gz",
	"windows/amd64": "windows-x86_64.zip",
}

// ExpectedBinaries  is a map of binaries agent needs to their project in the unified-release manager.
// The project names are those used in the "projects" list in the unified release manifest.
// See the sample manifests in the testdata directory.
var ExpectedBinaries = []BinarySpec{
<<<<<<< HEAD
	{BinaryName: "agentbeat", ProjectName: "beats", Platforms: AllPlatforms},
	{BinaryName: "apm-server", ProjectName: "apm-server", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}, {"windows", "x86_64"}, {"darwin", "x86_64"}}},
	{BinaryName: "cloudbeat", ProjectName: "cloudbeat", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}},
	{BinaryName: "cloud-defend", ProjectName: "cloud-defend", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}},
	{BinaryName: "connectors", ProjectName: "connectors", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}, PythonWheel: true},
	{BinaryName: "endpoint-security", ProjectName: "endpoint-dev", Platforms: AllPlatforms},
	{BinaryName: "fleet-server", ProjectName: "fleet-server", Platforms: AllPlatforms},
	{BinaryName: "pf-elastic-collector", ProjectName: "prodfiler", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}},
	{BinaryName: "pf-elastic-symbolizer", ProjectName: "prodfiler", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}},
	{BinaryName: "pf-host-agent", ProjectName: "prodfiler", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}},
=======
	{BinaryName: "agentbeat", ProjectName: "beats", Platforms: AllPlatforms, PackageTypes: pkgcommon.AllPackageTypes},
	{BinaryName: "apm-server", ProjectName: "apm-server", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}, {"windows", "x86_64"}, {"darwin", "x86_64"}}, PackageTypes: pkgcommon.AllPackageTypes},
	{BinaryName: "cloudbeat", ProjectName: "cloudbeat", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}, PackageTypes: pkgcommon.AllPackageTypes},
	{BinaryName: "connectors", ProjectName: "connectors", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}, PythonWheel: true, PackageTypes: pkgcommon.AllPackageTypes},
	{BinaryName: "endpoint-security", ProjectName: "endpoint-dev", Platforms: AllPlatforms, PackageTypes: []pkgcommon.PackageType{pkgcommon.RPM, pkgcommon.Deb, pkgcommon.Zip, pkgcommon.TarGz}},
	{BinaryName: "fleet-server", ProjectName: "fleet-server", Platforms: AllPlatforms, PackageTypes: pkgcommon.AllPackageTypes},
	{BinaryName: "pf-elastic-collector", ProjectName: "prodfiler", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}, PackageTypes: pkgcommon.AllPackageTypes},
	{BinaryName: "pf-elastic-symbolizer", ProjectName: "prodfiler", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}, PackageTypes: pkgcommon.AllPackageTypes},
	{BinaryName: "pf-host-agent", ProjectName: "prodfiler", Platforms: []Platform{{"linux", "x86_64"}, {"linux", "arm64"}}, PackageTypes: pkgcommon.AllPackageTypes},
>>>>>>> 9c7552fde1 (Remove endpoint security from linux containers (#6016))
}

type BinarySpec struct {
	BinaryName   string
	ProjectName  string
	Platforms    []Platform
	PythonWheel  bool
	PackageTypes []pkgcommon.PackageType
}

func (proj BinarySpec) SupportsPlatform(platform string) bool {
	for _, p := range proj.Platforms {
		if p.Platform() == platform {
			return true
		}
	}
	return false
}

func (proj BinarySpec) SupportsPackageType(pkgType pkgcommon.PackageType) bool {
	for _, p := range proj.PackageTypes {
		if p == pkgType {
			return true
		}
	}
	return false
}

func (proj BinarySpec) GetPackageName(version string, platform string) string {
	if proj.PythonWheel {
		return fmt.Sprintf("%s-%s.zip", proj.BinaryName, version)
	}
	return fmt.Sprintf("%s-%s-%s", proj.BinaryName, version, PlatformPackages[platform])
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
func DownloadManifest(ctx context.Context, manifest string) (Build, error) {
	manifestUrl, urlError := url.Parse(manifest)
	if urlError != nil {
		return Build{}, errorInvalidManifestURL
	}
	valid := false
	for _, manifestHost := range AllowedManifestHosts {
		if manifestHost == manifestUrl.Host {
			valid = true
		}
	}
	if !valid {
		log.Printf("Not allowed %s, valid ones are %+v", manifestUrl.Host, AllowedManifestHosts)
		return Build{}, errorNotAllowedManifestURL
	}
	sanitizedUrl := fmt.Sprintf("https://%s%s", manifestUrl.Host, manifestUrl.Path)
	f := func() (Build, error) { return downloadManifestData(ctx, sanitizedUrl) }
	manifestResponse, err := doWithRetries(f)
	if err != nil {
		return Build{}, fmt.Errorf("downloading manifest: %w", err)
	}
	if mg.Verbose() {
		log.Printf(">>>> Downloaded manifest %s", manifest)
		log.Printf(">>>> Packaging version: %s, build_id: %s, manifest_version:%s", manifestResponse.Version, manifestResponse.BuildID, manifestResponse.ManifestVersion)
	}
	return manifestResponse, nil
}

// DownloadComponents is going to download a set of components from the given manifest into the destination
// dropPath folder in order to later use that folder for packaging
func DownloadComponents(ctx context.Context, manifest string, platforms []string, dropPath string) error {
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
	for _, spec := range ExpectedBinaries {
		for _, platform := range platforms {
			targetPath := filepath.Join(dropPath)
			err := os.MkdirAll(targetPath, 0755)
			if err != nil {
				return fmt.Errorf("failed to create directory %s", targetPath)
			}
			log.Printf("+++ Prepare to download [%s] project [%s] for [%s]", spec.BinaryName, spec.ProjectName, platform)

			if !spec.SupportsPlatform(platform) {
				log.Printf(">>>>>>>>> Binary [%s] does not support platform [%s] ", spec.BinaryName, platform)
				continue
			}

			pkgURL, err := resolveManifestPackage(projects[spec.ProjectName], spec, majorMinorPatchVersion, platform)
			if err != nil {
				return err
			}

			for _, p := range pkgURL {
				log.Printf(">>>>>>>>> Downloading [%s] [%s] ", spec.BinaryName, p)
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

func resolveManifestPackage(project Project, spec BinarySpec, version string, platform string) ([]string, error) {
	var val Package
	var ok bool

	// Try the normal/easy case first
	packageName := spec.GetPackageName(version, platform)
	val, ok = project.Packages[packageName]
	if !ok {
		// If we didn't find it, it may be an Independent Agent Release, where
		// the opted-in projects will have a patch version one higher than
		// the rest of the projects, so we need to seek that out
		if mg.Verbose() {
			log.Printf(">>>>>>>>>>> Looking for package [%s] of type [%s]", spec.BinaryName, PlatformPackages[platform])
		}

		var foundIt bool
		for pkgName := range project.Packages {
			if strings.HasPrefix(pkgName, spec.BinaryName) {
				firstSplit := strings.Split(pkgName, spec.BinaryName+"-")
				if len(firstSplit) < 2 {
					continue
				}

				secondHalf := firstSplit[1]
				// Make sure we're finding one w/ the same required package type
				if strings.Contains(secondHalf, PlatformPackages[platform]) {

					// Split again after the version with the required package string
					secondSplit := strings.Split(secondHalf, "-"+PlatformPackages[platform])
					if len(secondSplit) < 2 {
						continue
					}

					// The first element after the split should normally be the version
					pkgVersion := secondSplit[0]
					if mg.Verbose() {
						log.Printf(">>>>>>>>>>> Using derived version for package [%s]: %s ", pkgName, pkgVersion)
					}

					// Create a project/package key with the package, derived version, and required package
					foundPkgKey := fmt.Sprintf("%s-%s-%s", spec.BinaryName, pkgVersion, PlatformPackages[platform])
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
	valid := false
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
