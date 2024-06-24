// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	defaultArtifactAPIURL = "https://artifacts-api.elastic.co/"

	artifactsAPIV1VersionBuildsEndpoint = "v1/versions/%s/builds/"
	artifactAPIV1BuildDetailsEndpoint   = "v1/versions/%s/builds/%s"

	artifactElasticAgentProject      = "elastic-agent-package"
	maxAttemptsForArtifactsAPICall   = 6
	retryIntervalForArtifactsAPICall = 5 * time.Second
)

var (
	ErrBuildNotFound     = errors.New("there are no builds that satisfy given conditions")
	ErrBadHTTPStatusCode = errors.New("bad http status code")
)

type Manifests struct {
	LastUpdateTime         string `json:"last-update-time"`
	SecondsSinceLastUpdate int    `json:"seconds-since-last-update"`
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

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type ArtifactAPIClientOpt func(aac *ArtifactAPIClient)

func WithUrl(url string) ArtifactAPIClientOpt {
	return func(aac *ArtifactAPIClient) { aac.url = url }
}

type logFunc func(format string, args ...interface{})

func WithLogFunc(logf logFunc) ArtifactAPIClientOpt {
	return func(aac *ArtifactAPIClient) { aac.logFunc = logf }
}

func WithHttpClient(client httpDoer) ArtifactAPIClientOpt {
	return func(aac *ArtifactAPIClient) { aac.c = client }
}

// ArtifactAPIClient is a small (and incomplete) client for the Elastic artifact API.
// More information about the API can be found at https://artifacts-api.elastic.co/v1
// which will print a list of available operations
type ArtifactAPIClient struct {
	c       httpDoer
	url     string
	logFunc logFunc
}

// NewArtifactAPIClient creates a new Artifact API client
func NewArtifactAPIClient(opts ...ArtifactAPIClientOpt) *ArtifactAPIClient {
	c := &ArtifactAPIClient{
		url:     defaultArtifactAPIURL,
		c:       new(http.Client),
		logFunc: func(string, ...interface{}) {},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetBuildsForVersion returns a list of builds for a specific version.
// version should be one of the version strings returned by the GetVersions (expected format is semver
// with optional prerelease but no build metadata, for example 8.9.0-SNAPSHOT)
func (aac ArtifactAPIClient) getBuildsForVersion(ctx context.Context, version string) (builds *VersionBuilds, err error) {
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
	resp, err := aac.getBuildsForVersion(ctx, version)
	if err != nil {
		return nil, fmt.Errorf("failed to get a list of builds: %w", err)
	}
	if len(resp.Builds) < offset+1 {
		return nil, ErrBuildNotFound
	}
	for _, buildID := range resp.Builds[offset:] {
		details, err := aac.getBuildDetails(ctx, version, buildID)
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
func (aac ArtifactAPIClient) getBuildDetails(ctx context.Context, version string, buildID string) (buildDetails *BuildDetails, err error) {
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

		aac.logFunc(
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

	d := json.NewDecoder(resp.Body)
	result := new(T)
	err := d.Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}
