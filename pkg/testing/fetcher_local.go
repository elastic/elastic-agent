// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type localFetcher struct {
	dir          string
	snapshotOnly bool
}

type localFetcherOpt func(f *localFetcher)

// WithLocalSnapshotOnly sets the LocalFetcher to only pull the snapshot build.
func WithLocalSnapshotOnly() localFetcherOpt {
	return func(f *localFetcher) {
		f.snapshotOnly = true
	}
}

// LocalFetcher returns a fetcher that pulls the binary of the Elastic Agent from a local location.
func LocalFetcher(dir string, opts ...localFetcherOpt) Fetcher {
	f := &localFetcher{
		dir: dir,
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

// Name returns a unique name for the fetcher.
func (f *localFetcher) Name() string {
	return "local"
}

// Fetch fetches the Elastic Agent and places the resulting binary at the path.
func (f *localFetcher) Fetch(_ context.Context, operatingSystem string, architecture string, version string) (FetcherResult, error) {
	suffix, err := GetPackageSuffix(operatingSystem, architecture)
	if err != nil {
		return nil, err
	}
	mainBuild := fmt.Sprintf("elastic-agent-%s-%s", version, suffix)
	mainBuildPath := filepath.Join(f.dir, mainBuild)
	build := mainBuild
	buildPath := mainBuildPath
	_, err = os.Stat(buildPath)
	if err != nil || f.snapshotOnly {
		// try to use a snapshot (or always with snapshotOnly)
		build = fmt.Sprintf("elastic-agent-%s-SNAPSHOT-%s", version, suffix)
		buildPath = filepath.Join(f.dir, build)
	}
	_, err = os.Stat(buildPath)
	if err != nil {
		return nil, fmt.Errorf("failed to find build at %s: %w", f.dir, err)
	}
	return &localFetcherResult{src: f.dir, path: build}, nil
}

type localFetcherResult struct {
	src  string
	path string
}

// Name is the name of the fetched result.
func (r *localFetcherResult) Name() string {
	return r.path
}

// Fetch performs the actual fetch into the provided directory.
func (r *localFetcherResult) Fetch(_ context.Context, _ Logger, dir string) error {
	fullPath := filepath.Join(r.src, r.path)

	reader, err := os.Open(fullPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", fullPath, err)
	}
	defer reader.Close()

	path := filepath.Join(dir, r.path)
	w, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer w.Close()

	_, err = io.Copy(w, reader)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	err = w.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync file %s: %w", path, err)
	}
	return nil
}
