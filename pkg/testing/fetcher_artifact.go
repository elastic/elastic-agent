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

	var uri string
	var prevErr error
	if !f.snapshotOnly {
		uri, prevErr = findURI(ctx, f.doer, version)
	}
	preVersion := version
	version, _ = splitBuildID(version)
	if uri == "" {
		if !strings.HasSuffix(version, "-SNAPSHOT") {
			version += "-SNAPSHOT"
		}
		uri, err = findURI(ctx, f.doer, version)
		if err != nil {
			return nil, fmt.Errorf("failed to find snapshot URI for version %s: %w (previous error: %w)", preVersion, err, prevErr)
		}
	}

	path := fmt.Sprintf("elastic-agent-%s-%s", version, suffix)
	downloadSrc := fmt.Sprintf("%s%s", uri, path)
	return &artifactResult{
		doer: f.doer,
		src:  downloadSrc,
		path: path,
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
	err := DownloadPackage(ctx, l, r.doer, r.src, filepath.Join(dir, r.path))
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", r.src, err)
	}

	// fetch package hash
	err = DownloadPackage(ctx, l, r.doer, r.src+hashExt, filepath.Join(dir, r.path+hashExt))
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", r.src, err)
	}

	return nil
}

func findURI(ctx context.Context, doer httpDoer, version string) (string, error) {
	version, buildID := splitBuildID(version)
	artifactsURI := fmt.Sprintf("https://artifacts-api.elastic.co/v1/search/%s/elastic-agent", version)
	req, err := http.NewRequestWithContext(ctx, "GET", artifactsURI, nil)
	if err != nil {
		return "", err
	}
	resp, err := doer.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s; bad status: %s", artifactsURI, resp.Status)
	}

	body := struct {
		Packages map[string]interface{} `json:"packages"`
	}{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&body); err != nil {
		return "", err
	}

	if len(body.Packages) == 0 {
		return "", fmt.Errorf("no packages found in repo")
	}

	for k, pkg := range body.Packages {
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
			if buildID == "" {
				// no build id, first is selected
				return fmt.Sprintf("%s/beats/elastic-agent/", uri[:index]), nil
			}
			if strings.Contains(uri, fmt.Sprintf("%s-%s", stripSnapshot(version), buildID)) {
				return fmt.Sprintf("%s/beats/elastic-agent/", uri[:index]), nil
			}
		}
	}

	if buildID == "" {
		return "", fmt.Errorf("uri not detected")
	}
	return "", fmt.Errorf("uri not detected with specific buildid %s", buildID)
}

func splitBuildID(version string) (string, string) {
	split := strings.SplitN(version, "+", 2)
	if len(split) == 1 {
		// no build ID
		return split[0], ""
	}
	return split[0], split[1]
}

func stripSnapshot(version string) string {
	if strings.HasSuffix(version, "-SNAPSHOT") {
		return strings.TrimSuffix(version, "-SNAPSHOT")
	}
	return version
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
