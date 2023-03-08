package testing

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var packageArchMap = map[string]string{
	"linux-amd64":   "linux-x86_64.tar.gz",
	"linux-arm64":   "linux-arm64.tar.gz",
	"windows-amd64": "windows-x86_64.zip",
	"darwin-amd64":  "darwin-x86_64.tar.gz",
	"darwin-arm64":  "darwin-aarch64.tar.gz",
}

type snapshotFetcher struct {
	version    string
	binaryPath string
}

// SnapshotFetcher returns a fetcher that pulls the binary of the Elastic Agent from snapshot builds.
func SnapshotFetcher() Fetcher {
	return &snapshotFetcher{}
}

// Fetch fetches the Elastic Agent and places the resulting binary at the path.
func (f *snapshotFetcher) Fetch(ctx context.Context, operatingSystem string, architecture string, version string, path string) error {
	key := fmt.Sprintf("%s-%s", operatingSystem, architecture)
	suffix, ok := packageArchMap[key]
	if !ok {
		return fmt.Errorf("not supported os/arch combination for downloading: %s/%s", operatingSystem, architecture)
	}

	snapshotURI, err := findSnapshotURI(ctx, version)
	if err != nil {
		return err
	}
	downloadPath := fmt.Sprintf("%s/beats/elastic-agent/elastic-agent-%s-SNAPSHOT-%s", snapshotURI, version, suffix)

	dir, err := ioutil.TempDir("", "agent-testing")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	packageFile := filepath.Join(dir, fmt.Sprintf("elastic-agent-%s-SNAPSHOT-%s", version, suffix))

	err = downloadPackage(ctx, downloadPath, packageFile)
	if err != nil {
		return err
	}
	err = untar(packageFile)
	if err != nil {
		return err
	}

	return nil
}

func findSnapshotURI(ctx context.Context, version string) (string, error) {
	artifactsURI := fmt.Sprintf("https://artifacts-api.elastic.co/v1/search/%s-SNAPSHOT/elastic-agent", version)
	req, err := http.NewRequestWithContext(ctx, "GET", artifactsURI, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
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
		return "", fmt.Errorf("no packages found in snapshot repo")
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
			return uri[:index], nil
		}
	}

	return "", fmt.Errorf("uri not detected")
}

func downloadPackage(ctx context.Context, downloadPath string, packageFile string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", downloadPath, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
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
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		return err
	}
	return nil
}

func untar(archivePath string) error {
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
	extractDir := filepath.Dir(archivePath)

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
		default:
			// skip unknown types
		}
	}
	return nil
}
