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
	"regexp"
	"strings"
	"time"

	"github.com/magefile/mage/mg"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent/dev-tools/packaging"
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
func DownloadComponents(ctx context.Context, expectedBinaries []packaging.BinarySpec, manifest string, platforms []string, dropPath string) error {
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
	for _, spec := range expectedBinaries {
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

			resolvedPackage, err := ResolveManifestPackage(projects[spec.ProjectName], spec, majorMinorPatchVersion, platform)
			if err != nil {
				return err
			}

			for _, p := range resolvedPackage.URLs {
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

type ResolvedPackage struct {
	Name          string
	ActualVersion string
	URLs          []string
}

func ResolveManifestPackage(project Project, spec packaging.BinarySpec, dependencyVersion string, platform string) (*ResolvedPackage, error) {

	// Try the normal/easy case first
	packageName := spec.GetPackageName(dependencyVersion, platform)
	if mg.Verbose() {
		log.Printf(">>>>>>>>>>> Got packagename [%s], looking for exact match", packageName)
	}

	if exactMatch, ok := project.Packages[packageName]; ok {
		// We found the exact filename we are looking for
		if mg.Verbose() {
			log.Printf(">>>>>>>>>>> Found exact match packageName for [%s, %s]: %s", project.Branch, project.CommitHash, exactMatch)
		}

		return &ResolvedPackage{
			Name:          packageName,
			ActualVersion: dependencyVersion,
			URLs:          []string{exactMatch.URL, exactMatch.ShaURL, exactMatch.AscURL},
		}, nil
	}

	// If we didn't find it, it may be an Independent Agent Release, where
	// the opted-in projects will have a patch version one higher than
	// the rest of the projects, so we "relax" the version constraint
	return resolveManifestPackageUsingRelaxedVersion(project, spec, dependencyVersion, platform)
}

func resolveManifestPackageUsingRelaxedVersion(project Project, spec packaging.BinarySpec, dependencyVersion string, platform string) (*ResolvedPackage, error) {
	// start with the rendered package name
	packageName := spec.GetPackageName(dependencyVersion, platform)

	// Find the original version in the rendered filename
	versionIndex := strings.Index(packageName, dependencyVersion)
	if versionIndex == -1 {
		return nil, fmt.Errorf("no exact match and filename %q does not seem to contain dependencyVersion %q to try a fallback", packageName, dependencyVersion)
	}

	// obtain a regexp from the exact version string that allows for some flexibility on patch version, prerelease and build metadata tokens
	relaxedVersion, err := relaxVersion(dependencyVersion)
	if err != nil {
		return nil, fmt.Errorf("relaxing dependencyVersion %q: %w", dependencyVersion, err)
	}

	if mg.Verbose() {
		log.Printf(">>>>>>>>>>> Couldn't find exact match, relaxing agent dependencyVersion to %s", relaxedVersion)
	}

	// locate the original version in the filename and substitute the relaxed version regexp, quoting everything around that
	relaxedPackageName := regexp.QuoteMeta(packageName[:versionIndex])
	relaxedPackageName += `(?P<version>` + relaxedVersion + `)`
	relaxedPackageName += regexp.QuoteMeta(packageName[versionIndex+len(dependencyVersion):])

	if mg.Verbose() {
		log.Printf(">>>>>>>>>>> Attempting to match a filename with %s", relaxedPackageName)
	}

	relaxedPackageNameRegexp, err := regexp.Compile(relaxedPackageName)
	if err != nil {
		return nil, fmt.Errorf("compiling relaxed package name regex %q: %w", relaxedPackageName, err)
	}

	for pkgName, pkg := range project.Packages {
		if mg.Verbose() {
			log.Printf(">>>>>>>>>>> Evaluating filename %s", pkgName)
		}
		if submatches := relaxedPackageNameRegexp.FindStringSubmatch(pkgName); len(submatches) > 0 {
			if mg.Verbose() {
				log.Printf(">>>>>>>>>>> Found matching packageName for [%s, %s]: %s", project.Branch, project.CommitHash, pkgName)
			}
			return &ResolvedPackage{
				Name:          pkgName,
				ActualVersion: submatches[1],
				URLs:          []string{pkg.URL, pkg.ShaURL, pkg.AscURL},
			}, nil
		}
	}

	return nil, fmt.Errorf("package [%s] not found in project manifest at %s using relaxed version %q", packageName, project.ExternalArtifactsManifestURL, relaxedPackageName)
}

// versionRegexp is taken from https://semver.org/ (see the FAQ section/Is there a suggested regular expression (RegEx) to check a SemVer string?)
const versionRegexp = `^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`
const anyPatchVersionRegexp = `(?:0|[1-9]\d*)`

var versionRegExp = regexp.MustCompile(versionRegexp)

func relaxVersion(version string) (string, error) {
	matchIndices := versionRegExp.FindSubmatchIndex([]byte(version))
	// Matches index pairs are (0,1) for the whole regexp and (2,3) for the patch group
	// check that we have matched correctly
	if len(matchIndices) < 4 {
		return "", fmt.Errorf("failed to match regexp for version [%s]", version)
	}

	// take the starting index of the patch version
	patchStartIndex := matchIndices[2]
	// copy everything before the patch version escaping the regexp
	relaxedVersion := regexp.QuoteMeta(version[:patchStartIndex])
	// add the patch regexp
	relaxedVersion += anyPatchVersionRegexp
	// check if there's more characters after the patch version
	remainderIndex := matchIndices[3]
	if remainderIndex < len(version) {
		// This is a looser regexp that allows anything beyond the major version to change (while still enforcing a valid patch version though)
		// see TestResolveManifestPackage/Independent_Agent_Staging_8.14_apm-server and TestResolveManifestPackage/Independent_Agent_Staging_8.14_endpoint-dev
		// Be more relaxed and allow for any character sequence after this
		relaxedVersion += `.*`
	}
	return relaxedVersion, nil
}

func DownloadPackage(ctx context.Context, downloadUrl string, target string) error {
	parsedURL, errorUrl := url.Parse(downloadUrl)
	if errorUrl != nil {
		return errorInvalidManifestURL
	}
	valid := false
	for _, manifestHost := range AllowedManifestHosts {
		if manifestHost == parsedURL.Hostname() {
			valid = true
		}
	}
	if !valid {
		log.Printf("Not allowed %s, valid ones are %+v", parsedURL.Hostname(), AllowedManifestHosts)
		return errorNotAllowedManifestURL
	}
	cleanUrl := fmt.Sprintf("https://%s%s", parsedURL.Host, parsedURL.Path)
	_, err := doWithRetries(func() (string, error) { return downloadFile(ctx, cleanUrl, target) })
	return err
}
