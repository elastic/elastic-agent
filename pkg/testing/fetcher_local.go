package testing

import (
	"context"
	"io/ioutil"
	"path/filepath"
)

type localFetcher struct {
	version    string
	binaryPath string
}

// LocalFetcher returns a fetcher that pulls the binary of the Elastic Agent from a local location.
func LocalFetcher(version string, path string) Fetcher {
	return &localFetcher{
		version:    version,
		binaryPath: path,
	}
}

// Fetch fetches the Elastic Agent and places the resulting binary at the path.
func (f *localFetcher) Fetch(_ context.Context, operatingSystem string, _ string, version string, dir string) error {
	if version != f.version {
		return ErrVersionMismatch
	}
	src, err := ioutil.ReadFile(f.binaryPath)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "elastic-agent")
	if operatingSystem == "windows" {
		path += ".exe"
	}
	err = ioutil.WriteFile(path, src, 0755)
	if err != nil {
		return err
	}
	return nil
}
