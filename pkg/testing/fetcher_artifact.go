// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
func (f *artifactFetcher) Fetch(ctx context.Context, operatingSystem string, architecture string, version string, packageFormat string) (FetcherResult, error) {
	suffix, err := GetPackageSuffix(operatingSystem, architecture, packageFormat)
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
		return nil, fmt.Errorf("failed to find artifact URI for version %s: %w", ver, err)
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

func findURI(ctx context.Context, doer httpDoer, version *semver.ParsedSemVer) (string, error) {
	// if it's the latest snapshot of a version, we can find a build ID and build the URI in the same manner
	if version.IsSnapshot() {
		// if we know the exact build ID, we can build the URI right away
		if version.BuildMetadata() != "" {
			return fmt.Sprintf("https://snapshots.elastic.co/%s-%s/downloads/beats/elastic-agent/", version.CoreVersion(), version.BuildMetadata()), nil
		}

		buildID, err := findLatestSnapshot(ctx, doer, version.CoreVersion())
		if err != nil {
			return "", fmt.Errorf("failed to find snapshot information for version %q: %w", version, err)
		}
		return fmt.Sprintf("https://snapshots.elastic.co/%s-%s/downloads/beats/elastic-agent/", version.CoreVersion(), buildID), nil
	}

	// otherwise, we're looking for a publicly released version
	return "https://artifacts.elastic.co/downloads/beats/elastic-agent/", nil
}

func findLatestSnapshot(ctx context.Context, doer httpDoer, version string) (buildID string, err error) {
	latestSnapshotURI := fmt.Sprintf("https://snapshots.elastic.co/latest/%s-SNAPSHOT.json", version)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, latestSnapshotURI, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request to the snapshot API: %w", err)
	}

	resp, err := doer.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return "", fmt.Errorf("snapshot for version %q not found", version)

	case http.StatusOK:
		var info struct {
			BuildID string `json:"build_id"`
		}

		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&info); err != nil {
			return "", err
		}

		parts := strings.Split(info.BuildID, "-")
		if len(parts) != 2 {
			return "", fmt.Errorf("wrong format for a build ID: %s", info.BuildID)
		}

		return parts[1], nil

	default:
		return "", fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, latestSnapshotURI)
	}
}

func DownloadPackage(ctx context.Context, l Logger, doer httpDoer, downloadPath string, packageFile string) error {
	for i := 0; i < 3; i++ {
		err := func() error {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			return downloadPackage(ctx, l, doer, downloadPath, packageFile)
		}()
		if err == nil {
			return nil
		}
		l.Logf("Download artifact from %s failed: %s", downloadPath, err)
	}
	return fmt.Errorf("downloading package failed after 3 retries")
}

func downloadPackage(ctx context.Context, l Logger, doer httpDoer, downloadPath string, packageFile string) error {
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
