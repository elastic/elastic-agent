package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	defaultArtifactAPIURL = "https://artifacts-api.elastic.co/"

	artifactsAPIV1VersionsEndpoint      = "v1/versions/"
	artifactsAPIV1VersionBuildsEndpoint = "v1/versions/%s/builds/"
	artifactAPIV1BuildDetailsEndpoint   = "v1/versions/%s/builds/%s"
	//artifactAPIV1SearchVersionPackage = "v1/search/%s/%s"
)

var ErrBadHTTPStatusCode = errors.New("bad http status code")

type VersionList struct {
	Versions  []string `json:"versions"`
	Aliases   []string `json:"aliases"`
	Manifests struct {
		LastUpdateTime         string `json:"last-update-time"`
		SecondsSinceLastUpdate int    `json:"seconds-since-last-update"`
	} `json:"manifests"`
}

type VersionBuilds struct {
	Builds    []string `json:"builds"`
	Manifests struct {
		LastUpdateTime         string `json:"last-update-time"`
		SecondsSinceLastUpdate int    `json:"seconds-since-last-update"`
	} `json:"manifests"`
}

type Package struct {
	URL        string `json:"url"`
	ShaURL     string `json:"sha_url"`
	AscURL     string `json:"asc_url"`
	Type       string `json:"type"`
	Attributes struct {
		ArtifactNoKpi string `json:"artifactNoKpi"`
		Internal      string `json:"internal"`
		ArtifactID    string `json:"artifact_id"`
		Oss           string `json:"oss"`
		Group         string `json:"group"`
	} `json:"attributes"`
}

type Project struct {
	Branch                       string             `json:"branch"`
	CommitHash                   string             `json:"commit_hash"`
	CommitURL                    string             `json:"commit_url"`
	ExternalArtifactsManifestURL string             `json:"external_artifacts_manifest_url"`
	BuildDurationSeconds         int                `json:"build_duration_seconds"`
	Packages                     map[string]Package `json:"packages"`
	Dependencies                 []any              `json:"dependencies"`
}

type BuildDetails struct {
	Build struct {
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
	} `json:"build"`
	Manifests struct {
		LastUpdateTime         string `json:"last-update-time"`
		SecondsSinceLastUpdate int    `json:"seconds-since-last-update"`
	} `json:"manifests"`
}

type SearchPackageResult struct {
	Packages  map[string]Package `json:"packages"`
	Manifests struct {
		LastUpdateTime         string `json:"last-update-time"`
		SecondsSinceLastUpdate int    `json:"seconds-since-last-update"`
	} `json:"manifests"`
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type ArtifactAPIClient struct {
	c      httpDoer
	apiURL string
}

func (aac ArtifactAPIClient) GetVersions(ctx context.Context) (list *VersionList, err error) {
	joinedURL, err := url.JoinPath(aac.apiURL, artifactsAPIV1VersionsEndpoint)
	if err != nil {
		err = fmt.Errorf("composing URL with %q %q: %w", aac.apiURL, artifactsAPIV1VersionsEndpoint, err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinedURL, nil)

	if err != nil {
		err = fmt.Errorf("composing request for getting versions: %w", err)
		return
	}

	resp, err := aac.c.Do(req)
	if err != nil {
		err = fmt.Errorf("executing http request %v: %w", req, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("%d: %w", resp.StatusCode, ErrBadHTTPStatusCode)
		return
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("reading response body: %w", err)
		return
	}
	list = new(VersionList)
	err = json.Unmarshal(respBytes, list)

	if err != nil {
		err = fmt.Errorf("unmarshaling version list: %w", err)
		return
	}

	return list, nil
}

func (aac ArtifactAPIClient) GetBuildsForVersion(ctx context.Context, version string) (builds *VersionBuilds, err error) {
	joinedURL, err := url.JoinPath(aac.apiURL, fmt.Sprintf(artifactsAPIV1VersionBuildsEndpoint, version))
	if err != nil {
		err = fmt.Errorf("composing URL with %q %q: %w", aac.apiURL, fmt.Sprintf(artifactsAPIV1VersionBuildsEndpoint, version), err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinedURL, nil)

	if err != nil {
		err = fmt.Errorf("composing request for getting versions: %w", err)
		return
	}

	resp, err := aac.c.Do(req)
	if err != nil {
		err = fmt.Errorf("executing http request %v: %w", req, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("%d: %w", resp.StatusCode, ErrBadHTTPStatusCode)
		return
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("reading response body: %w", err)
		return
	}
	builds = new(VersionBuilds)
	err = json.Unmarshal(respBytes, builds)

	if err != nil {
		err = fmt.Errorf("unmarshaling build list: %w", err)
		return
	}

	return builds, nil
}

func (aac ArtifactAPIClient) GetBuildDetails(ctx context.Context, version string, buildID string) (buildDetails *BuildDetails, err error) {
	joinedURL, err := url.JoinPath(aac.apiURL, fmt.Sprintf(artifactAPIV1BuildDetailsEndpoint, version, buildID))
	if err != nil {
		err = fmt.Errorf("composing URL with %q %q: %w", aac.apiURL, fmt.Sprintf(artifactAPIV1BuildDetailsEndpoint, version, buildID), err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinedURL, nil)

	if err != nil {
		err = fmt.Errorf("composing request for getting build details: %w", err)
		return
	}

	resp, err := aac.c.Do(req)
	if err != nil {
		err = fmt.Errorf("executing http request %v: %w", req, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("%d: %w", resp.StatusCode, ErrBadHTTPStatusCode)
		return
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("reading response body: %w", err)
		return
	}
	buildDetails = new(BuildDetails)
	err = json.Unmarshal(respBytes, buildDetails)

	if err != nil {
		err = fmt.Errorf("unmarshaling build details: %w", err)
		return
	}

	return buildDetails, nil
}

type ArtifactAPIClientOpt func(aac *ArtifactAPIClient)

func WithUrl(url string) ArtifactAPIClientOpt {
	return func(aac *ArtifactAPIClient) { aac.apiURL = url }
}

func WithHttpClient(client httpDoer) ArtifactAPIClientOpt {
	return func(aac *ArtifactAPIClient) { aac.c = client }
}

func NewArtifactAPIClient(opts ...ArtifactAPIClientOpt) *ArtifactAPIClient {
	c := &ArtifactAPIClient{
		apiURL: defaultArtifactAPIURL,
		c:      new(http.Client),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}
