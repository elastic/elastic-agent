// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	semver "github.com/elastic/elastic-agent/pkg/version"
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type artifactFetcher struct {
	snapshotOnly bool

	doer httpDoer
}

type artifactFetcherOpt func(f *artifactFetcher)

// WithArtifactSnapshotOnly sets the ArtifactFetcher to only pull the snapshot build.
func WithArtifactSnapshotOnly() artifactFetcherOpt {
	return func(f *artifactFetcher) {
		f.snapshotOnly = true
	}
}

// ArtifactFetcher returns a fetcher that pulls the binary of the Elastic Agent from the Elastic artifacts API.
//
// It tries to pull the latest version and if it cannot find that version it tries to pull a SNAPSHOT build for
// that version.
func ArtifactFetcher(opts ...artifactFetcherOpt) Fetcher {
	f := &artifactFetcher{
		doer: http.DefaultClient,
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

// Name returns a unique name for the fetcher.
func (f *artifactFetcher) Name() string {
	return "artifact"
}

// Fetch fetches the Elastic Agent and places the resulting binary at the path.
func (f *artifactFetcher) Fetch(ctx context.Context, operatingSystem string, architecture string, version string) (FetcherResult, error) {
	suffix, err := GetPackageSuffix(operatingSystem, architecture)
	if err != nil {
		return nil, err
	}

	ver, err := semver.ParseVersion(version)
	if err != nil {
		return nil, fmt.Errorf("invalid version: %q: %w", ver, err)
	}

	if f.snapshotOnly && !ver.IsSnapshot() {
		if ver.Prerelease() == "" {
			ver = semver.NewParsedSemVer(ver.Major(), ver.Minor(), ver.Patch(), "SNAPSHOT", ver.BuildMetadata())
		} else {
			ver = semver.NewParsedSemVer(ver.Major(), ver.Minor(), ver.Patch(), ver.Prerelease()+"-SNAPSHOT", ver.BuildMetadata())
		}
	}

	uri, err := findURI(ctx, f.doer, ver)
	if err != nil {
		return nil, fmt.Errorf("failed to find snapshot URI for version %s: %w", ver, err)
	}

	// this remote path cannot have the build metadata in it
	srcPath := fmt.Sprintf("elastic-agent-%s-%s", ver.VersionWithPrerelease(), suffix)
	downloadSrc := fmt.Sprintf("%s%s", uri, srcPath)

	return &artifactResult{
		doer: f.doer,
		src:  downloadSrc,
		// this path must have the build metadata in it, so we don't mix such files with
		// no build-specific snapshots. If build metadata is empty, it's just `srcPath`.
		path: filepath.Join(ver.BuildMetadata(), srcPath),
	}, nil
}

type artifactResult struct {
	doer httpDoer
	src  string
	path string
}

// Name is the name of the fetched result.
func (r *artifactResult) Name() string {
	return r.path
}

// Fetch performs the actual fetch into the provided directory.
func (r *artifactResult) Fetch(ctx context.Context, l Logger, dir string) error {
	dst := filepath.Join(dir, r.Name())
	// the artifact name can contain a subfolder that needs to be created
	err := os.MkdirAll(filepath.Dir(dst), 0755)
	if err != nil {
		return fmt.Errorf("failed to create path %q: %w", dst, err)
	}

	err = DownloadPackage(ctx, l, r.doer, r.src, dst)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", r.src, err)
	}

	// fetch package hash
	err = DownloadPackage(ctx, l, r.doer, r.src+extHash, dst+extHash)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", r.src, err)
	}

	// fetch package asc
	err = DownloadPackage(ctx, l, r.doer, r.src+extAsc, dst+extAsc)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", r.src, err)
	}

	return nil
}

type projectResponse struct {
	Packages map[string]interface{} `json:"packages"`
}

type projectsResponse struct {
	ElasticPackage projectResponse `json:"elastic-agent-package"`
}

type manifestResponse struct {
	Projects projectsResponse `json:"projects"`
}

func findBuild(ctx context.Context, doer httpDoer, version *semver.ParsedSemVer) (*projectResponse, error) {
	// e.g. https://snapshots.elastic.co/8.13.0-l5snflwr/manifest-8.13.0-SNAPSHOT.json
	manifestURI := fmt.Sprintf("https://snapshots.elastic.co/%s-%s/manifest-%s-SNAPSHOT.json", version.CoreVersion(), version.BuildMetadata(), version.CoreVersion())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s; bad status: %s", manifestURI, resp.Status)
	}

	var body manifestResponse

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&body); err != nil {
		return nil, err
	}

	return &body.Projects.ElasticPackage, nil
}

func findVersion(ctx context.Context, doer httpDoer, version *semver.ParsedSemVer) (*projectResponse, error) {
	artifactsURI := fmt.Sprintf("https://artifacts-api.elastic.co/v1/search/%s/elastic-agent", version.VersionWithPrerelease())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactsURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s; bad status: %s", artifactsURI, resp.Status)
	}

	var body projectResponse

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func findURI(ctx context.Context, doer httpDoer, version *semver.ParsedSemVer) (string, error) {
	var (
		project *projectResponse
		err     error
	)

	if version.BuildMetadata() != "" {
		project, err = findBuild(ctx, doer, version)
	} else {
		project, err = findVersion(ctx, doer, version)
	}

	if err != nil {
		return "", fmt.Errorf("failed to find package URL: %w", err)
	}

	if len(project.Packages) == 0 {
		return "", fmt.Errorf("no packages found in repo")
	}

	for k, pkg := range project.Packages {
		pkgMap, ok := pkg.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("content of '%s' is not a map", k)
		}

		uriVal, found := pkgMap["url"]
		if !found {
			return "", fmt.Errorf("item '%s' does not contain url", k)
		}

		uri, ok := uriVal.(string)
		if !ok {
			return "", fmt.Errorf("uri is not a string")
		}

		// Because we're iterating over a map from the API response,
		// the order is random and some elements there do not contain the
		// `/beats/elastic-agent/` substring, so we need to go through the
		// whole map before returning an error.
		//
		// One of the elements that might be there and do not contain this
		// substring is the `elastic-agent-shipper`, whose URL is something like:
		// https://snapshots.elastic.co/8.7.0-d050210c/downloads/elastic-agent-shipper/elastic-agent-shipper-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
		index := strings.Index(uri, "/beats/elastic-agent/")
		if index != -1 {
			if version.BuildMetadata() == "" {
				// no build id, first is selected
				return fmt.Sprintf("%s/beats/elastic-agent/", uri[:index]), nil
			}
			if strings.Contains(uri, fmt.Sprintf("%s-%s", version.CoreVersion(), version.BuildMetadata())) {
				return fmt.Sprintf("%s/beats/elastic-agent/", uri[:index]), nil
			}
		}
	}

	if version.BuildMetadata() == "" {
		return "", fmt.Errorf("uri for version %q not detected", version)
	}
	return "", fmt.Errorf("uri not detected with specific build ID %q", version.BuildMetadata())
}

func DownloadPackage(ctx context.Context, l Logger, doer httpDoer, downloadPath string, packageFile string) error {
	l.Logf("Downloading artifact from %s", downloadPath)

	req, err := http.NewRequestWithContext(ctx, "GET", downloadPath, nil)
	if err != nil {
		return err
	}
	resp, err := doer.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s; bad status: %s", downloadPath, resp.Status)
	}

	w, err := os.Create(packageFile)
	if err != nil {
		return err
	}
	defer w.Close()

	var reader io.Reader
	var size int
	length := resp.Header.Get("Content-Length")
	if length != "" {
		size, _ = strconv.Atoi(length)
	}
	if size > 0 {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		progress := newWriteProgress(ctx, l, uint64(size))
		reader = io.TeeReader(resp.Body, progress)
	} else {
		reader = resp.Body
	}

	_, err = io.Copy(w, reader)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", packageFile, err)
	}
	err = w.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync file %s: %w", packageFile, err)
	}

	l.Logf("Completed downloading artifact from %s", downloadPath)
	return nil
}

type writeProgress struct {
	logger    Logger
	total     uint64
	completed atomic.Uint64
}

func newWriteProgress(ctx context.Context, l Logger, total uint64) *writeProgress {
	wp := &writeProgress{
		logger: l,
		total:  total,
	}
	go wp.printProgress(ctx)
	return wp
}

func (wp *writeProgress) Write(p []byte) (int, error) {
	n := len(p)
	wp.completed.Add(uint64(n))
	return n, nil
}

func (wp *writeProgress) printProgress(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			wp.logger.Logf("Downloading artifact progress %.2f%%", float64(wp.completed.Load())/float64(wp.total)*100.0)
		}
	}
}
