// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	semver "github.com/elastic/elastic-agent/pkg/version"
)

type localFetcher struct {
	dir          string
	snapshotOnly bool
	binaryName   string
}

type localFetcherOpt func(f *localFetcher)

// WithLocalSnapshotOnly sets the LocalFetcher to only pull the snapshot build.
func WithLocalSnapshotOnly() localFetcherOpt {
	return func(f *localFetcher) {
		f.snapshotOnly = true
	}
}

// WithCustomBinaryName sets the binary to a custom name, the default is `elastic-agent`
func WithCustomBinaryName(name string) localFetcherOpt {
	return func(f *localFetcher) {
		f.binaryName = name
	}
}

// LocalFetcher returns a fetcher that pulls the binary of the Elastic Agent from a local location.
func LocalFetcher(dir string, opts ...localFetcherOpt) Fetcher {
	f := &localFetcher{
		dir:        dir,
		binaryName: "elastic-agent",
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
func (f *localFetcher) Fetch(_ context.Context, operatingSystem string, architecture string, version string, packageFormat string) (FetcherResult, error) {
	suffix, err := GetPackageSuffix(operatingSystem, architecture, packageFormat)
	if err != nil {
		return nil, err
	}

	ver, err := semver.ParseVersion(version)
	if err != nil {
		return nil, fmt.Errorf("invalid version: %q: %w", ver, err)
	}

	mainBuildfmt := "%s-%s-%s"
	if f.snapshotOnly && !ver.IsSnapshot() {
		if ver.Prerelease() == "" {
			ver = semver.NewParsedSemVer(ver.Major(), ver.Minor(), ver.Patch(), "SNAPSHOT", ver.BuildMetadata())
		} else {
			ver = semver.NewParsedSemVer(ver.Major(), ver.Minor(), ver.Patch(), ver.Prerelease()+"-SNAPSHOT", ver.BuildMetadata())
		}
	}

	var buildPath string

	const earlyReleaseVersionSuffix = `build\d{14}`
	// exclude non-snapshot and +buildYYYYMMDDHHMMSS from this path for local fetcher (I am not even sure that the build ID makes sense in the local fetcher)
	matchesEarlyReleaseVersion, err := regexp.Match(earlyReleaseVersionSuffix, []byte(ver.BuildMetadata()))
	if err != nil {
		return nil, fmt.Errorf("error checking %q for early release version", ver.BuildMetadata())
	}

	if ver.IsSnapshot() && !matchesEarlyReleaseVersion {
		build := fmt.Sprintf(mainBuildfmt, f.binaryName, ver.VersionWithPrerelease(), suffix)
		buildPath = filepath.Join(ver.BuildMetadata(), build)
	} else {
		buildPath = fmt.Sprintf(mainBuildfmt, f.binaryName, ver.String(), suffix)
	}

	fullPath := filepath.Join(f.dir, buildPath)
	_, err = os.Stat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to find build at %s: %w", f.dir, err)
	}
	return &localFetcherResult{src: f.dir, path: buildPath}, nil
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
	src := filepath.Join(r.src, r.path)
	dst := filepath.Join(dir, r.path)
	// the artifact name can contain a subfolder that needs to be created
	err := os.MkdirAll(filepath.Dir(dst), 0755)
	if err != nil {
		return fmt.Errorf("failed to create path %q: %w", dst, err)
	}
	err = copyFile(src, dst)
	if err != nil {
		return fmt.Errorf("error copying file: %w", err)
	}

	// fetch artifact hash
	err = copyFile(src+extHash, dst+extHash)
	if err != nil {
		return fmt.Errorf("error copying file: %w", err)
	}

	return nil
}

func copyFile(src, dst string) error {
	reader, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", src, err)
	}
	defer reader.Close()

	w, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", dst, err)
	}
	defer w.Close()

	_, err = io.Copy(w, reader)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", dst, err)
	}
	err = w.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync file %s: %w", dst, err)
	}
	return nil
}
