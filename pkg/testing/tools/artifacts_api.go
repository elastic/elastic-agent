// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"time"

	"github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/version"
)

const (
	defaultArtifactAPIURL = "https://artifacts-api.elastic.co/"

	artifactsAPIV1VersionsEndpoint      = "v1/versions/"
	artifactsAPIV1VersionBuildsEndpoint = "v1/versions/%s/builds/"
	artifactAPIV1BuildDetailsEndpoint   = "v1/versions/%s/builds/%s"
	// artifactAPIV1SearchVersionPackage = "v1/search/%s/%s"

	artifactElasticAgentProject = "elastic-agent-package"
	artifactReleaseCDN          = "https://artifacts.elastic.co/downloads/beats/elastic-agent"

	maxAttemptsForArtifactsAPICall   = 6
	retryIntervalForArtifactsAPICall = 5 * time.Second
)

var (
	ErrLatestVersionNil        = errors.New("latest version is nil")
	ErrSnapshotVersionsEmpty   = errors.New("snapshot list is nil")
	ErrInvalidVersionRetrieved = errors.New("invalid version retrieved from artifact API")
	ErrBuildNotFound           = errors.New("there are no build that satisfy given conditions")

	ErrBadHTTPStatusCode = errors.New("bad http status code")
)

type Manifests struct {
	LastUpdateTime         string `json:"last-update-time"`
	SecondsSinceLastUpdate int    `json:"seconds-since-last-update"`
}

type VersionList struct {
	Versions  []string  `json:"versions"`
	Aliases   []string  `json:"aliases"`
	Manifests Manifests `json:"manifests"`
}

type VersionBuilds struct {
	Builds    []string  `json:"builds"`
	Manifests Manifests `json:"manifests"`
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

type Project struct {
	Branch                       string             `json:"branch"`
	CommitHash                   string             `json:"commit_hash"`
	CommitURL                    string             `json:"commit_url"`
	ExternalArtifactsManifestURL string             `json:"external_artifacts_manifest_url"`
	BuildDurationSeconds         int                `json:"build_duration_seconds"`
	Packages                     map[string]Package `json:"packages"`
	Dependencies                 []Dependency       `json:"dependencies"`
}

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

type BuildDetails struct {
	Build     Build
	Manifests Manifests `json:"manifests"`
}

type SearchPackageResult struct {
	Packages  map[string]Package `json:"packages"`
	Manifests Manifests          `json:"manifests"`
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type ArtifactAPIClientOpt func(aac *ArtifactAPIClient)

func WithUrl(url string) ArtifactAPIClientOpt {
	return func(aac *ArtifactAPIClient) { aac.url = url }
}

func WithCDNUrl(url string) ArtifactAPIClientOpt {
	return func(aac *ArtifactAPIClient) { aac.cdnURL = url }
}

func WithHttpClient(client httpDoer) ArtifactAPIClientOpt {
	return func(aac *ArtifactAPIClient) { aac.c = client }
}

// ArtifactAPIClient is a small (and incomplete) client for the Elastic artifact API.
// More information about the API can be found at https://artifacts-api.elastic.co/v1
// which will print a list of available operations
type ArtifactAPIClient struct {
	c      httpDoer
	url    string
	cdnURL string

	logger logger
}

// NewArtifactAPIClient creates a new Artifact API client
func NewArtifactAPIClient(logger logger, opts ...ArtifactAPIClientOpt) *ArtifactAPIClient {
	c := &ArtifactAPIClient{
		url:    defaultArtifactAPIURL,
		cdnURL: artifactReleaseCDN,
		c:      new(http.Client),
		logger: logger,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetVersions returns a list of versions as server by the Artifact API along with some aliases and manifest information
func (aac ArtifactAPIClient) GetVersions(ctx context.Context) (list *VersionList, err error) {
	joinedURL, err := aac.composeURL(artifactsAPIV1VersionsEndpoint)
	if err != nil {
		return nil, err
	}

	resp, err := aac.createAndPerformRequest(ctx, joinedURL)
	if err != nil {
		return nil, fmt.Errorf("getting versions: %w", err)
	}

	defer resp.Body.Close()
	return checkResponseAndUnmarshal[VersionList](resp)
}

// RemoveUnreleasedVersions from the list
// There is a period of time when a version is already marked as released
// but not published on the CDN. This happens when we already have build candidates.
// This function checks if a version marked as released actually has published artifacts.
// If there are no published artifacts, the version is removed from the list.
func (aac ArtifactAPIClient) RemoveUnreleasedVersions(ctx context.Context, vList *VersionList) error {
	suffix, err := testing.GetPackageSuffix(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("failed to generate the artifact suffix: %w", err)
	}

	results := make([]string, 0, len(vList.Versions))

	for _, versionItem := range vList.Versions {
		parsedVersion, err := version.ParseVersion(versionItem)
		if err != nil {
			return fmt.Errorf("failed to parse version %s: %w", versionItem, err)
		}
		// we check only release versions without `-SNAPSHOT`
		if parsedVersion.Prerelease() != "" {
			results = append(results, versionItem)
			continue
		}
		url := fmt.Sprintf("%s/elastic-agent-%s-%s", aac.cdnURL, versionItem, suffix)
		// using method `HEAD` to avoid downloading the file
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			return fmt.Errorf("failed to create an HTTP request to %q: %w", url, err)
		}

		resp, err := aac.c.Do(req)
		if err != nil {
			return fmt.Errorf("failed to request %q: %w", url, err)
		}

		// we don't read the response. However, we must drain when it's present,
		// so the connection can be re-used later, see:
		// https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/net/http/response.go;l=62-64
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusNotFound:
			continue
		case http.StatusOK:
			results = append(results, versionItem)
			continue
		default:
			return fmt.Errorf("unexpected status code from %s - %d", url, resp.StatusCode)
		}
	}

	// nothing changed
	if len(vList.Versions) == len(results) {
		return nil
	}

	vList.Versions = results

	return nil
}

// GetBuildsForVersion returns a list of builds for a specific version.
// version should be one of the version strings returned by the GetVersions (expected format is semver
// with optional prerelease but no build metadata, for example 8.9.0-SNAPSHOT)
func (aac ArtifactAPIClient) GetBuildsForVersion(ctx context.Context, version string) (builds *VersionBuilds, err error) {
	joinedURL, err := aac.composeURL(fmt.Sprintf(artifactsAPIV1VersionBuildsEndpoint, version))
	if err != nil {
		return nil, err
	}

	resp, err := aac.createAndPerformRequest(ctx, joinedURL)
	if err != nil {
		return nil, fmt.Errorf("getting builds for version %s: %w", version, err)
	}

	defer resp.Body.Close()
	return checkResponseAndUnmarshal[VersionBuilds](resp)
}

// FindBuild returns a build of the given `version` that does not match the
// `excludeHash` commit hash. It searches for a matching build from the latest
// to the oldest, starting the search at the `offset` index in the list of builds.
// Setting `offset` to 0 includes all builds, 1 skips the latest, and so forth.
// If there are no builds matching these conditions, returns `ErrBuildNotFound`.
func (aac ArtifactAPIClient) FindBuild(ctx context.Context, version, excludeHash string, offset int) (buildDetails *BuildDetails, err error) {
	resp, err := aac.GetBuildsForVersion(ctx, version)
	if err != nil {
		return nil, fmt.Errorf("failed to get a list of builds: %w", err)
	}
	if len(resp.Builds) < offset+1 {
		return nil, ErrBuildNotFound
	}
	for _, buildID := range resp.Builds[offset:] {
		details, err := aac.GetBuildDetails(ctx, version, buildID)
		if err != nil {
			return nil, fmt.Errorf("failed to get build information for %q: %w", buildID, err)
		}
		if details.Build.Projects[artifactElasticAgentProject].CommitHash != excludeHash {
			return details, nil
		}
	}

	return nil, ErrBuildNotFound
}

// GetBuildDetails returns the list of project and artifacts related to a specific build.
// Version parameter format follows semver (without build metadata) and buildID format is <major>.<minor>.<patch>-<buildhash> as returned by
// GetBuildsForVersion()
func (aac ArtifactAPIClient) GetBuildDetails(ctx context.Context, version string, buildID string) (buildDetails *BuildDetails, err error) {
	joinedURL, err := aac.composeURL(fmt.Sprintf(artifactAPIV1BuildDetailsEndpoint, version, buildID))
	if err != nil {
		return nil, err
	}

	resp, err := aac.createAndPerformRequest(ctx, joinedURL)
	if err != nil {
		return nil, fmt.Errorf("getting build details for version %s buildID %s: %w", version, buildID, err)
	}

	defer resp.Body.Close()
	return checkResponseAndUnmarshal[BuildDetails](resp)
}

func (aac ArtifactAPIClient) composeURL(relativePath string) (string, error) {
	joinedURL, err := url.JoinPath(aac.url, relativePath)
	if err != nil {
		return "", fmt.Errorf("composing URL with %q %q: %w", aac.url, relativePath, err)
	}

	return joinedURL, nil
}

func (aac ArtifactAPIClient) createAndPerformRequest(ctx context.Context, URL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		err = fmt.Errorf("composing request: %w", err)
		return nil, err
	}

	// Make the request with retries as the artifacts API can sometimes be flaky.
	var resp *http.Response
	// TODO (once we're on Go 1.22): replace with for numAttempts := range maxAttemptsForArtifactsAPICall {
	for numAttempts := 0; numAttempts < maxAttemptsForArtifactsAPICall; numAttempts++ {
		resp, err = aac.c.Do(req)

		// If there is no error, no need to retry the request.
		if err == nil {
			break
		}

		// If the context was cancelled or timed out, return early
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf(
				"executing http request %s %s (attempt %d of %d) cancelled or timed out: %w",
				req.Method, req.URL, numAttempts+1, maxAttemptsForArtifactsAPICall, err,
			)
		}

		aac.logger.Logf(
			"failed attempt %d of %d executing http request %s %s: %s; retrying after %v...",
			numAttempts+1, maxAttemptsForArtifactsAPICall, req.Method, req.URL, err.Error(), retryIntervalForArtifactsAPICall,
		)
		time.Sleep(retryIntervalForArtifactsAPICall)
	}

	if err != nil {
		return nil, fmt.Errorf(
			"failed executing http request %s %s after %d attempts: %w",
			req.Method, req.URL, maxAttemptsForArtifactsAPICall, err,
		)
	}

	return resp, nil
}

func checkResponseAndUnmarshal[T any](resp *http.Response) (*T, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d: %w", resp.StatusCode, ErrBadHTTPStatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	result := new(T)
	err = json.Unmarshal(respBytes, result)

	if err != nil {
		return nil, fmt.Errorf("unmarshaling: %w", err)
	}

	return result, nil
}

type logger interface {
	Logf(format string, args ...any)
}

func (aac ArtifactAPIClient) GetLatestSnapshotVersion(ctx context.Context) (*version.ParsedSemVer, error) {
	vList, err := aac.GetVersions(ctx)
	if err != nil {
		return nil, err
	}

	if vList == nil {
		return nil, ErrSnapshotVersionsEmpty
	}

	sortedParsedVersions := make(version.SortableParsedVersions, 0, len(vList.Versions))
	for _, v := range vList.Versions {
		pv, err := version.ParseVersion(v)
		if err != nil {
			aac.logger.Logf("invalid version retrieved from artifact API: %q", v)
			return nil, ErrInvalidVersionRetrieved
		}
		sortedParsedVersions = append(sortedParsedVersions, pv)
	}

	if len(sortedParsedVersions) == 0 {
		return nil, ErrSnapshotVersionsEmpty
	}

	// normally the output of the versions returned by artifact API is already
	// sorted in ascending order.If we want to sort in descending order we need
	// to pass a sort.Reverse to sort.Sort.
	sort.Sort(sort.Reverse(sortedParsedVersions))

	var latestSnapshotVersion *version.ParsedSemVer
	// fetch the latest SNAPSHOT build
	for _, pv := range sortedParsedVersions {
		if pv.IsSnapshot() {
			latestSnapshotVersion = pv
			break
		}
	}
	if latestSnapshotVersion == nil {
		return nil, ErrLatestVersionNil
	}
	return latestSnapshotVersion, nil
}
