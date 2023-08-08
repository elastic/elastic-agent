// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
)

const hashExt = ".sha512"

var (
	// ErrUnsupportedPlatform returned when the operating system and architecture combination is not supported.
	ErrUnsupportedPlatform = errors.New("platform is not supported")
)

// packageArchMap provides a mapping for the endings of the builds of Elastic Agent based on the
// operating system and architecture.
var packageArchMap = map[string]string{
	"linux-amd64":   "linux-x86_64.tar.gz",
	"linux-arm64":   "linux-arm64.tar.gz",
	"windows-amd64": "windows-x86_64.zip",
	"darwin-amd64":  "darwin-x86_64.tar.gz",
	"darwin-arm64":  "darwin-aarch64.tar.gz",
}

// GetPackageSuffix returns the suffix ending for the builds of Elastic Agent based on the
// operating system and architecture.
func GetPackageSuffix(operatingSystem string, architecture string) (string, error) {
	suffix, ok := packageArchMap[fmt.Sprintf("%s-%s", operatingSystem, architecture)]
	if !ok {
		return "", fmt.Errorf("%w: %s/%s", ErrUnsupportedPlatform, operatingSystem, architecture)
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
	Fetch(ctx context.Context, operatingSystem string, architecture string, version string) (FetcherResult, error)
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
	return "", "", fmt.Errorf("unknown file extension type: %s", filepath.Ext(name))
}

// untar takes a .tar.gz and extracts its content
func untar(archivePath string, extractDir string) error {
	r, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	zr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}

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
		abs := filepath.Join(extractDir, f.Name)
		switch {
		case mode.IsRegular():
			// just to be sure, it should already be created by Dir type
			if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
				return fmt.Errorf("failed creating directory for file %s: %w", abs, err)
			}

			wf, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode.Perm())
			if err != nil {
				return fmt.Errorf("failed creating file %s: %w", abs, err)
			}

			_, err = io.Copy(wf, tr)
			if closeErr := wf.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
			if err != nil {
				return fmt.Errorf("error writing file %s: %w", abs, err)
			}
		case mode.IsDir():
			if err := os.MkdirAll(abs, 0755); err != nil {
				return fmt.Errorf("failed creating directory %s: %w", abs, err)
			}
		case mode.Type()&os.ModeSymlink == os.ModeSymlink:
			// just to be sure, it should already be created by Dir type
			if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
				return fmt.Errorf("failed creating directory for symlink %s: %w", abs, err)
			}
			if err := os.Symlink(f.Linkname, abs); err != nil {
				return fmt.Errorf("failed creating symlink %s: %w", abs, err)
			}
		default:
			// skip unknown types
		}
	}
	return nil
}

// unzip takes a .zip and extracts its content
func unzip(archivePath string, extractDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	unpackFile := func(f *zip.File) (err error) {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if cerr := rc.Close(); cerr != nil {
				err = multierror.Append(err, cerr)
			}
		}()

		fi := f.FileInfo()
		mode := fi.Mode()
		abs := filepath.Join(extractDir, f.Name)
		switch {
		case mode.IsRegular():
			// just to be sure, it should already be created by Dir type
			if err := os.MkdirAll(filepath.Dir(abs), f.Mode()); err != nil {
				return fmt.Errorf("failed creating directory for file %s: %w", abs, err)
			}

			f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return fmt.Errorf("failed creating file %s: %w", abs, err)
			}
			defer func() {
				if cerr := f.Close(); cerr != nil {
					err = multierror.Append(err, cerr)
				}
			}()

			if _, err = io.Copy(f, rc); err != nil {
				return fmt.Errorf("error writing file %s: %w", abs, err)
			}
		case mode.IsDir():
			if err := os.MkdirAll(abs, f.Mode()); err != nil {
				return fmt.Errorf("failed creating directory %s: %w", abs, err)
			}
		default:
			// skip unknown types
		}
		return nil
	}

	for _, f := range r.File {
		if err := unpackFile(f); err != nil {
			return err
		}
	}
	return nil
}
