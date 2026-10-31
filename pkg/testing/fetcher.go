// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"archive/tar"
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/klauspost/pgzip"
)

const extAsc = ".asc"
const extHash = ".sha512"

var (
	// ErrUnsupportedPlatform returned when the operating system and architecture combination is not supported.
	ErrUnsupportedPlatform = errors.New("platform is not supported")
)

// packageArchMap provides a mapping for the endings of the builds of Elastic Agent based on the
// operating system and architecture.
var packageArchMap = map[string]string{
	"linux-amd64-targz":  "linux-x86_64.tar.gz",
	"linux-amd64-deb":    "amd64.deb",
	"linux-amd64-rpm":    "x86_64.rpm",
	"linux-arm64-targz":  "linux-arm64.tar.gz",
	"linux-arm64-deb":    "arm64.deb",
	"linux-arm64-rpm":    "aarch64.rpm",
	"windows-amd64-zip":  "windows-x86_64.zip",
	"windows-arm64-zip":  "windows-arm64.zip",
	"darwin-amd64-targz": "darwin-x86_64.tar.gz",
	"darwin-arm64-targz": "darwin-aarch64.tar.gz",
}

// GetPackagePrefix returns the prefix right before the version component of the Elastic
// Agent's artifact name, based on the given parameter values.
func GetPackagePrefix(fipsOnly bool) string {
	if fipsOnly {
		return "fips-"
	}
	return ""
}

// GetPackageSuffix returns the suffix ending for the builds of Elastic Agent based on the
// operating system and architecture.
func GetPackageSuffix(operatingSystem string, architecture string, packageFormat string) (string, error) {
	suffix, ok := packageArchMap[fmt.Sprintf("%s-%s-%s", operatingSystem, architecture, packageFormat)]
	if !ok {
		return "", fmt.Errorf("%w: %s/%s/%s", ErrUnsupportedPlatform, operatingSystem, architecture, packageFormat)
	}
	return suffix, nil
}

// FetcherResult represents a pending result from the fetcher.
type FetcherResult interface {
	// Name is the name of the fetched result.
	Name() string
	// Fetch performs the actual fetch into the provided directory.
	Fetch(ctx context.Context, l Logger, dir string) error
}

// Fetcher provides a path for fetching the Elastic Agent compressed archive
// to extract and run for the integration test.
type Fetcher interface {
	// Name returns a unique name for the fetcher.
	//
	// This name is used as a caching key and if a build has already been fetched for a version then it will not
	// be fetched again as long as the same fetcher is being used.
	Name() string
	// Fetch fetches the Elastic Agent compressed archive to extract and run for the integration test.
	//
	// The extraction is handled by the caller. This should only download the file
	// and place it into the directory.
	Fetch(ctx context.Context, operatingSystem string, architecture string, version string, packageFormat string) (FetcherResult, error)
}

// fetchCache is global to all tests, reducing the time required to fetch the needed artifacts
// to only be need at the start of the first test.
var fetchCache map[string]*fetcherCache
var fetchCacheMx sync.Mutex

// fetcherCache provides a caching mechanism for only fetching what has not already been fetched.
type fetcherCache struct {
	mx  sync.Mutex
	dir string
}

// fetch either uses the cache result or performs a new fetch if the content is missing.
func (c *fetcherCache) fetch(ctx context.Context, l Logger, res FetcherResult) (string, error) {
	name := res.Name()
	src := filepath.Join(c.dir, name)
	_, err := os.Stat(src)
	if err == nil || os.IsExist(err) {
		l.Logf("Using existing artifact %s", name)
		return src, nil
	}
	err = res.Fetch(ctx, l, c.dir)
	if err != nil {
		return "", err
	}
	return src, nil
}

func splitFileType(name string) (string, string, error) {
	if strings.HasSuffix(name, ".tar.gz") {
		return strings.TrimSuffix(name, ".tar.gz"), ".tar.gz", nil
	}
	if strings.HasSuffix(name, ".zip") {
		return strings.TrimSuffix(name, ".zip"), ".zip", nil
	}
	if strings.HasSuffix(name, ".deb") {
		return strings.TrimSuffix(name, ".deb"), ".deb", nil
	}
	if strings.HasSuffix(name, ".rpm") {
		return strings.TrimSuffix(name, ".rpm"), ".rpm", nil
	}
	return "", "", fmt.Errorf("unknown file extension type: %s", filepath.Ext(name))
}

// untar takes a .tar.gz and extracts its content.
//
// The package is decompressed with pgzip rather than compress/gzip: extracting
// the ~1.3 GB agent package is bound by inflate, and pgzip runs the inflate in
// its own goroutine with read-ahead, which is ~25% faster for a single-member
// gzip stream and keeps the file writes off the decompressing goroutine.
//
// All paths are created through an os.Root for extractDir, so an entry cannot
// escape the extraction directory.
func untar(archivePath string, extractDir string) error {
	r, err := os.Open(archivePath) //nolint:gosec // G703: test helper opening the fetched test artifact
	if err != nil {
		return err
	}
	defer r.Close()

	zr, err := pgzip.NewReader(r)
	if err != nil {
		return err
	}
	defer zr.Close()

	root, err := os.OpenRoot(extractDir)
	if err != nil {
		return fmt.Errorf("failed opening extraction directory %s: %w", extractDir, err)
	}
	defer root.Close()

	tr := tar.NewReader(zr)

	for {
		f, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		fi := f.FileInfo()
		mode := fi.Mode()
		name := filepath.FromSlash(f.Name)
		switch {
		case mode.IsRegular():
			// just to be sure, it should already be created by Dir type
			if err := root.MkdirAll(filepath.Dir(name), 0755); err != nil {
				return fmt.Errorf("failed creating directory for file %s: %w", name, err)
			}

			wf, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode.Perm())
			if err != nil {
				return fmt.Errorf("failed creating file %s: %w", name, err)
			}

			_, err = io.Copy(wf, tr) //nolint:gosec // used only in tests
			if closeErr := wf.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
			if err != nil {
				return fmt.Errorf("error writing file %s: %w", name, err)
			}
		case mode.IsDir():
			if err := root.MkdirAll(name, 0755); err != nil {
				return fmt.Errorf("failed creating directory %s: %w", name, err)
			}
		case mode.Type()&os.ModeSymlink == os.ModeSymlink:
			// just to be sure, it should already be created by Dir type
			if err := root.MkdirAll(filepath.Dir(name), 0755); err != nil {
				return fmt.Errorf("failed creating directory for symlink %s: %w", name, err)
			}
			if err := root.Symlink(f.Linkname, name); err != nil {
				return fmt.Errorf("failed creating symlink %s: %w", name, err)
			}
		default:
			// skip unknown types
		}
	}
	return nil
}

// unzip takes a .zip and extracts its content.
//
// All paths are created through an os.Root for extractDir, so an entry cannot
// escape the extraction directory.
func unzip(archivePath string, extractDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	root, err := os.OpenRoot(extractDir)
	if err != nil {
		return fmt.Errorf("failed opening extraction directory %s: %w", extractDir, err)
	}
	defer root.Close()

	unpackFile := func(f *zip.File) (err error) {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if cerr := rc.Close(); cerr != nil {
				err = errors.Join(err, cerr)
			}
		}()

		fi := f.FileInfo()
		mode := fi.Mode()
		name := filepath.FromSlash(f.Name)
		switch {
		case mode.IsRegular():
			// just to be sure, it should already be created by Dir type
			if err := root.MkdirAll(filepath.Dir(name), 0755); err != nil {
				return fmt.Errorf("failed creating directory for file %s: %w", name, err)
			}

			f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
			if err != nil {
				return fmt.Errorf("failed creating file %s: %w", name, err)
			}
			defer func() {
				if cerr := f.Close(); cerr != nil {
					err = errors.Join(err, cerr)
				}
			}()

			//nolint:gosec // used only in tests
			if _, err = io.Copy(f, rc); err != nil {
				return fmt.Errorf("error writing file %s: %w", name, err)
			}
		case mode.IsDir():
			// os.Root.MkdirAll only accepts permission bits
			if err := root.MkdirAll(name, mode.Perm()); err != nil {
				return fmt.Errorf("failed creating directory %s: %w", name, err)
			}
		default:
			// skip unknown types
		}
		return nil
	}

	// Directories first and sequentially, so that the parallel file extraction
	// below never races on creating a parent directory with a specific mode.
	var files []*zip.File
	for _, f := range r.File {
		if f.FileInfo().Mode().IsDir() {
			if err := unpackFile(f); err != nil {
				return err
			}
			continue
		}
		files = append(files, f)
	}

	// Each zip entry is compressed independently, so unlike a tar.gz the
	// entries can be inflated in parallel. The agent package has a handful of
	// large component binaries, so the gain is bounded by the biggest entry.
	workers := runtime.GOMAXPROCS(0)
	if workers > len(files) {
		workers = len(files)
	}
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan *zip.File)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				if err := unpackFile(f); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	var firstErr error
loop:
	for _, f := range files {
		select {
		case jobs <- f:
		case firstErr = <-errs:
			break loop
		}
	}
	close(jobs)
	wg.Wait()
	close(errs)
	for err := range errs {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
