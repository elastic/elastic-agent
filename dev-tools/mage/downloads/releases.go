// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package downloads

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/cenkalti/backoff/v4"
)

// DownloadURLResolver interface to resolve URLs for downloadable artifacts
type DownloadURLResolver interface {
	Resolve() (url string, shaURL string, err error)
	Kind() string
}

// ArtifactURLResolver type to resolve the URL of artifacts that are currently in development, from the artifacts API
type ArtifactURLResolver struct {
	FullName string
	Name     string
	Version  string
}

// NewArtifactURLResolver creates a new resolver for artifacts that are currently in development, from the artifacts API
func NewArtifactURLResolver(fullName string, name string, version string) DownloadURLResolver {
	return &ArtifactURLResolver{
		FullName: fullName,
		Name:     name,
		Version:  version,
	}
}

func (r *ArtifactURLResolver) Kind() string {
	return fmt.Sprintf("Unified snapshot resolver: %s", r.FullName)
}

// Resolve returns the URL of a released artifact, which its full name is defined in the first argument,
// from Elastic's artifact repository, building the JSON path query based on the full name
func (r *ArtifactURLResolver) Resolve() (string, string, error) {
	resolvedVersion, err := GetElasticArtifactVersion(r.Version)
	if err != nil {
		return "", "", fmt.Errorf("failed to get version %s: %w", r.Version, err)
	}
	r.Version = resolvedVersion

	fullName := strings.ReplaceAll(r.FullName, r.Version, resolvedVersion)
	r.FullName = fullName

	artifactName := r.FullName
	artifact := r.Name
	version := r.Version

	exp := getExponentialBackoff(time.Minute)

	retryCount := 1

	body := []byte{}

	tmpVersion := version
	hasCommit := SnapshotHasCommit(version)
	if hasCommit {
		logger.Log(context.Background(), TraceLevel, "Removing SNAPSHOT from version including commit",
			slog.String("resolver", r.Kind()),
			slog.String("version", version),
		)

		// remove the SNAPSHOT from the VERSION as the artifacts API supports commits in the version, but without the snapshot suffix
		tmpVersion = GetCommitVersion(version)
	}

	apiStatus := func() error {
		url := fmt.Sprintf("https://artifacts-api.elastic.co/v1/search/%s/%s?x-elastic-no-kpi=true", tmpVersion, artifact)
		req := httpRequest{
			URL: url,
		}
		bodyStr, err := get(req)
		if err != nil {
			logger.Warn("Resolver failed",
				slog.String("kind", r.Kind()),
				slog.String("artifact", artifact),
				slog.String("artifactName", artifactName),
				slog.String("version", tmpVersion),
				slog.String("error", err.Error()),
				slog.Int("retry", retryCount),
				slog.String("statusEndpoint", url),
				slog.Duration("elapsedTime", exp.GetElapsedTime()),
				slog.String("resp", bodyStr),
			)
			retryCount++

			return err
		}

		body = []byte(bodyStr)
		return nil
	}

	err = backoff.Retry(apiStatus, exp)
	if err != nil {
		logger.Error("Failed to get artifact",
			slog.String("resolver", r.Kind()),
			slog.String("artifact", artifact),
			slog.String("artifactName", artifactName),
			slog.String("version", tmpVersion),
		)
		return "", "", err
	}

	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		logger.Error("Could not parse the response body for the artifact",
			slog.String("resolver", r.Kind()),
			slog.String("artifact", artifact),
			slog.String("artifactName", artifactName),
			slog.String("version", tmpVersion),
		)
		return "", "", err
	}

	logger.Log(context.Background(), TraceLevel, "Resolver succeeded",
		slog.String("resolver", r.Kind()),
		slog.Int("retries", retryCount),
		slog.String("artifact", artifact),
		slog.String("artifactName", artifactName),
		slog.Duration("elapsedTime", exp.GetElapsedTime()),
		slog.String("version", tmpVersion),
	)

	if hasCommit {
		// remove commit from the artifact as it comes like this: elastic-agent-8.0.0-abcdef-SNAPSHOT-darwin-x86_64.tar.gz
		artifactName = RemoveCommitFromSnapshot(artifactName)
	}

	packagesObject := jsonParsed.Path("packages")
	// we need to get keys with dots using Search instead of Path
	downloadObject := packagesObject.Search(artifactName)
	if downloadObject == nil {
		logger.Error("ArtifactURLResolver object not found in Artifact API",
			slog.String("artifact", artifact),
			slog.String("name", artifactName),
			slog.String("version", version),
		)
		return "", "", fmt.Errorf("object not found in Artifact API")
	}

	downloadURL, ok := downloadObject.Path("url").Data().(string)
	if !ok {
		return "", "", fmt.Errorf("key 'url' does not exist for artifact %s", artifact)
	}
	downloadshaURL, ok := downloadObject.Path("sha_url").Data().(string)
	if !ok {
		return "", "", fmt.Errorf("key 'sha_url' does not exist for artifact %s", artifact)
	}

	return downloadURL, downloadshaURL, nil
}

type ArtifactsSnapshotVersion struct {
	Host string
}

func newArtifactsSnapshotCustom(host string) *ArtifactsSnapshotVersion {
	return &ArtifactsSnapshotVersion{
		Host: host,
	}
}

// GetSnapshotArtifactVersion returns the current version:
// Uses artifacts-snapshot.elastic.co to retrieve the latest version of a SNAPSHOT artifact
// 1. Elastic's artifact repository, building the JSON path query based
// If the version is a SNAPSHOT including a commit, then it will directly use the version without checking the artifacts API
// i.e. GetSnapshotArtifactVersion("$VERSION-abcdef-SNAPSHOT")
func (as *ArtifactsSnapshotVersion) GetSnapshotArtifactVersion(project string, version string) (string, error) {
	cacheKey := fmt.Sprintf("%s/%s/latest/%s.json", as.Host, project, version)

	elasticVersionsMutex.RLock()
	val, ok := elasticVersionsCache[cacheKey]
	elasticVersionsMutex.RUnlock()
	if ok {
		logger.Debug("ArtifactsSnapshotVersion Retrieving version from local cache",
			slog.String("URL", cacheKey),
			slog.String("version", val),
		)
		return val, nil
	}

	if SnapshotHasCommit(version) {
		elasticVersionsMutex.Lock()
		elasticVersionsCache[cacheKey] = version
		elasticVersionsMutex.Unlock()
		return version, nil
	}

	exp := getExponentialBackoff(time.Minute)

	retryCount := 1

	body := []byte{}

	apiStatus := func() error {
		url := cacheKey
		r := httpRequest{
			URL: url,
		}
		bodyStr, err := get(r)
		if err != nil {
			logger.Warn("ArtifactsSnapshotVersion failed",
				slog.String("version", version),
				slog.String("error", err.Error()),
				slog.Int("retry", retryCount),
				slog.String("statusEndpoint", url),
				slog.Duration("elapsedTime", exp.GetElapsedTime()),
				slog.String("resp", bodyStr),
			)
			retryCount++

			return err
		}

		body = []byte(bodyStr)
		return nil
	}

	err := backoff.Retry(apiStatus, exp)
	if err != nil {
		return "", err
	}

	type ArtifactsSnapshotResponse struct {
		Version     string `json:"version"`      // example value: "8.8.3-SNAPSHOT"
		BuildID     string `json:"build_id"`     // example value: "8.8.3-b1d8691a"
		ManifestURL string `json:"manifest_url"` // example value: https://artifacts-snapshot.elastic.co/beats/8.8.3-b1d8691a/manifest-8.8.3-SNAPSHOT.json
		SummaryURL  string `json:"summary_url"`  // example value: https://artifacts-snapshot.elastic.co/beats/8.8.3-b1d8691a/summary-8.8.3-SNAPSHOT.html
	}
	response := ArtifactsSnapshotResponse{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		logger.Error("ArtifactsSnapshotVersion Could not parse the response body to retrieve the version",
			slog.String("error", err.Error()),
			slog.String("version", version),
			slog.String("body", string(body)),
		)

		return "", fmt.Errorf("could not parse the response body to retrieve the version: %w", err)
	}

	hashParts := strings.Split(response.BuildID, "-")
	if (len(hashParts) < 2) || (hashParts[1] == "") {
		logger.Error("ArtifactsSnapshotVersion Could not parse the build_id to retrieve the version hash", slog.String("buildId", response.BuildID))
		return "", fmt.Errorf("could not parse the build_id to retrieve the version hash: %s", response.BuildID)
	}
	hash := hashParts[1]
	parsedVersion := hashParts[0]

	latestVersion := fmt.Sprintf("%s-%s-SNAPSHOT", parsedVersion, hash)

	logger.Debug("ArtifactsSnapshotVersion got latest version for current version",
		slog.String("alias", version),
		slog.String("version", latestVersion),
	)

	elasticVersionsMutex.Lock()
	elasticVersionsCache[cacheKey] = latestVersion
	elasticVersionsMutex.Unlock()

	return latestVersion, nil
}

// NewArtifactSnapshotURLResolver creates a new resolver for artifacts that are currently in development, from the artifacts API
func NewArtifactSnapshotURLResolver(fullName string, name string, project string, version string) DownloadURLResolver {
	return newCustomSnapshotURLResolver(fullName, name, project, version, "https://artifacts-snapshot.elastic.co")
}

// For testing purposes
func newCustomSnapshotURLResolver(fullName string, name string, project string, version string, host string) DownloadURLResolver {
	// resolve version alias
	resolvedVersion, err := newArtifactsSnapshotCustom(host).GetSnapshotArtifactVersion(project, version)
	if err != nil {
		return nil
	}
	return &ArtifactsSnapshotURLResolver{
		FullName:        fullName,
		Name:            name,
		Project:         project,
		Version:         resolvedVersion,
		SnapshotApiHost: host,
	}
}

// ArtifactsSnapshotURLResolver type to resolve the URL of artifacts that are currently in development, from the artifacts API
// Takes the artifacts staged for inclusion in the next unified snapshot, before one is available.
type ArtifactsSnapshotURLResolver struct {
	FullName        string
	Name            string
	Version         string
	Project         string
	SnapshotApiHost string
}

func (asur *ArtifactsSnapshotURLResolver) Kind() string {
	return fmt.Sprintf("Project snapshot resolver: %s", asur.FullName)
}

func (asur *ArtifactsSnapshotURLResolver) Resolve() (string, string, error) {
	artifactName := asur.FullName
	artifact := asur.Name
	version := asur.Version
	commit, err := ExtractCommitHash(version)
	semVer := GetVersion(version)
	if err != nil {
		logger.Info("ArtifactsSnapshotURLResolver version does not contain a commit hash, it is not a snapshot",
			slog.String("artifact", artifact),
			slog.String("artifactName", artifactName),
			slog.String("project", asur.Project),
			slog.String("version", version),
		)
		return "", "", err
	}

	exp := getExponentialBackoff(time.Minute)

	retryCount := 1

	body := []byte{}

	apiStatus := func() error {
		// https://artifacts-snapshot.elastic.co/beats/8.9.0-d1b14479/manifest-8.9.0-SNAPSHOT.json
		url := fmt.Sprintf("%s/%s/%s-%s/manifest-%s-SNAPSHOT.json", asur.SnapshotApiHost, asur.Project, semVer, commit, semVer)
		r := httpRequest{URL: url}
		bodyStr, err := get(r)
		if err != nil {
			logger.Warn("resolver failed",
				slog.String("kind", asur.Kind()),
				slog.String("artifact", artifact),
				slog.String("artifactName", artifactName),
				slog.String("version", version),
				slog.String("error", err.Error()),
				slog.Int("retry", retryCount),
				slog.String("statusEndpoint", url),
				slog.Duration("elapsedTime", exp.GetElapsedTime()),
				slog.String("resp", bodyStr),
			)
			retryCount++

			return err
		}

		body = []byte(bodyStr)
		return nil
	}

	err = backoff.Retry(apiStatus, exp)
	if err != nil {
		return "", "", err
	}

	var jsonParsed map[string]interface{}
	err = json.Unmarshal(body, &jsonParsed)
	if err != nil {
		logger.Error("Could not parse the response body for the artifact",
			slog.String("kind", asur.Kind()),
			slog.String("artifact", artifact),
			slog.String("artifactName", artifactName),
			slog.String("project", asur.Project),
			slog.String("version", version),
		)
		return "", "", err
	}

	url, shaURL, err := findSnapshotPackage(jsonParsed, artifactName)
	if err != nil {
		return "", "", err
	}

	logger.Log(context.Background(), TraceLevel, "Resolver succeeded",
		slog.String("kind", asur.Kind()),
		slog.Int("retries", retryCount),
		slog.String("artifact", artifact),
		slog.String("artifactName", artifactName),
		slog.Duration("elapsedTime", exp.GetElapsedTime()),
		slog.String("project", asur.Project),
		slog.String("version", version),
	)

	return url, shaURL, nil
}

func findSnapshotPackage(jsonParsed map[string]interface{}, fullName string) (string, string, error) {
	projects, ok := jsonParsed["projects"].(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("key 'projects' does not exist")
	}

	for _, project := range projects {
		projectPackages, ok := project.(map[string]interface{})["packages"].(map[string]interface{})
		if !ok {
			continue
		}

		pack, ok := projectPackages[fullName].(map[string]interface{})

		if !ok {
			continue
		}

		return pack["url"].(string), pack["sha_url"].(string), nil

	}
	return "", "", fmt.Errorf("package %s not found", fullName)
}

// ReleaseURLResolver type to resolve the URL of downloads that are currently published in elastic.co/downloads
type ReleaseURLResolver struct {
	Project  string
	FullName string
	Name     string
}

// NewReleaseURLResolver creates a new resolver for downloads that are currently published in elastic.co/downloads
func NewReleaseURLResolver(project string, fullName string, name string) *ReleaseURLResolver {
	return &ReleaseURLResolver{
		FullName: fullName,
		Name:     name,
		Project:  project,
	}
}

func (r *ReleaseURLResolver) Kind() string {
	return fmt.Sprintf("Official release resolver: %s", r.FullName)
}

// Resolve resolves the URL of a download, which is located in the Elastic. It will use a HEAD request
// and if it returns a 200 OK it will return the URL of both file and its SHA512 file
func (r *ReleaseURLResolver) Resolve() (string, string, error) {
	url := fmt.Sprintf("https://artifacts.elastic.co/downloads/%s/%s/%s", r.Project, r.Name, r.FullName)
	shaURL := fmt.Sprintf("%s.sha512", url)

	exp := getExponentialBackoff(time.Minute)
	retryCount := 1
	found := false

	apiStatus := func() error {
		req := httpRequest{URL: url}
		bodyStr, err := head(req)
		if err != nil {
			logger.Debug("Resolver failed",
				slog.String("kind", r.Kind()),
				slog.String("error", err.Error()),
				slog.Int("retry", retryCount),
				slog.String("statusEndpoint", url),
				slog.Duration("elapsedTime", exp.GetElapsedTime()),
				slog.String("resp", bodyStr),
			)

			retryCount++

			return err
		}

		found = true
		logger.Info("Download was found in the Elastic downloads API",
			slog.String("kind", r.Kind()),
			slog.Int("retries", retryCount),
			slog.String("statusEndpoint", url),
			slog.Duration("elapsedTime", exp.GetElapsedTime()),
		)

		return nil
	}

	err := backoff.Retry(apiStatus, exp)
	if err != nil {
		return "", "", err
	}

	if !found {
		return "", "", fmt.Errorf("download could not be found at the Elastic downloads API")
	}

	return url, shaURL, nil
}
