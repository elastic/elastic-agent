package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/uuid"
	"golang.org/x/exp/maps"
)

const (
	defaultAPIURL         = "https://artifacts-snapshot.elastic.co"
	beatsManifestEndpoint = "beats/latest/%s.json"
)

type ArtifactSnapshotClient struct {
	url        string
	httpClient *http.Client
}

type ArtifactsManifestResponse struct {
	BuildID     string `json:"build_id"`     // example value: "8.8.3-b1d8691a"
	Version     string `json:"version"`      // example value: "8.8.3-SNAPSHOT"
	ManifestURL string `json:"manifest_url"` // example value: https://artifacts-snapshot.elastic.co/beats/8.8.3-b1d8691a/manifest-8.8.3-SNAPSHOT.json
	SummaryURL  string `json:"summary_url"`  // example value: https://artifacts-snapshot.elastic.co/beats/8.8.3-b1d8691a/summary-8.8.3-SNAPSHOT.html
}

type Projects struct {
	Projects map[string]ProjectData `json:"projects"`
}

type ProjectData struct {
	Branch     string                 `json:"branch"`
	CommitHash string                 `json:"commit_hash"`
	CommitURL  string                 `json:"commit_url"`
	Packages   map[string]PackageData `json:"packages"`
}

type PackageData struct {
	Url          string            `json:"url"`
	ShaUrl       string            `json:"sha_url"`
	Type         string            `json:"type"`
	Architecture string            `json:"architecture"`
	OS           []string          `json:"os"`
	Attributes   map[string]string `json:"attributes"`
}

type PackageRequest struct {
	// heartbeat-8.10.0-SNAPSHOT-linux-x86_64.tar.gz
	Name       string
	TargetPath string
}

func NewArtifactSnapshotClient() *ArtifactSnapshotClient {
	return &ArtifactSnapshotClient{
		url:        defaultAPIURL,
		httpClient: new(http.Client),
	}
}

func (c *ArtifactSnapshotClient) DownloadPackages(ctx context.Context, packageRequests []PackageRequest, version string) error {
	manResponse, err := c.getManifestResponse(ctx, version)
	if err != nil {
		return fmt.Errorf("getting manifest response: %w", err)
	}
	manifestPackages, err := c.getManifestPackages(ctx, manResponse.ManifestURL)
	if err != nil {
		return fmt.Errorf("getting manifest packages: %w", err)
	}
	for _, pkg := range packageRequests {
		pkgData, ok := manifestPackages[pkg.Name]
		if !ok {
			return fmt.Errorf("package %s not found in manifest", pkg)
		}
		fmt.Printf("Downloading package %s to %s \n", pkg.Name, pkg.TargetPath)
		err := c.downloadPackage(ctx, pkgData, pkg.TargetPath)
		if err != nil {
			return fmt.Errorf("downloading package: %w", err)
		}
	}
	return nil
}

func (c *ArtifactSnapshotClient) getManifestResponse(ctx context.Context, version string) (*ArtifactsManifestResponse, error) {
	endpoint := fmt.Sprintf(beatsManifestEndpoint, version)
	url := fmt.Sprintf("%s/%s", c.url, endpoint)
	response, err := c.createAndPerformRequest(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("creating and performing request: %w", err)
	}
	manResponse, err := checkResponseAndUnmarshal[ArtifactsManifestResponse](response)
	if err != nil {
		return nil, fmt.Errorf("checking response and unmarshalling: %w", err)
	}
	return manResponse, nil
}

func (c *ArtifactSnapshotClient) getManifestPackages(ctx context.Context, manifestURL string) (map[string]PackageData, error) {
	response, err := c.createAndPerformRequest(ctx, manifestURL)
	if err != nil {
		return nil, fmt.Errorf("creating and performing request: %w", err)
	}
	manResponse, err := checkResponseAndUnmarshal[Projects](response)
	if err != nil {
		return nil, fmt.Errorf("checking response and unmarshalling: %w", err)
	}
	allPackages := make(map[string]PackageData)
	for _, v := range maps.Values(manResponse.Projects) {
		for k, pack := range v.Packages {
			allPackages[k] = pack
		}
	}
	return allPackages, nil
}

func (c *ArtifactSnapshotClient) downloadPackage(ctx context.Context, pkg PackageData, destination string) error {
	return downloadFile(pkg.Url, destination)
}

func downloadFile(url string, path string) error {
	var filePath string
	if path == "" {
		tempParentDir := filepath.Join(os.TempDir(), uuid.NewString())
		filePath = filepath.Join(tempParentDir, uuid.NewString())
		path = filePath
	} else {
		filePath = filepath.Join(path, uuid.NewString())
	}

	tempFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer tempFile.Close()
	exp := getExponentialBackOff(3)

	retryCount := 1
	var fileReader io.ReadCloser
	download := func() error {
		resp, err := http.Get(url)
		if err != nil {
			retryCount++
			return fmt.Errorf("getting url %s: %w", url, err)
		}
		fileReader = resp.Body

		return nil
	}

	err = backoff.Retry(download, exp)
	if err != nil {
		return err
	}
	defer fileReader.Close()

	_, err = io.Copy(tempFile, fileReader)
	if err != nil {
		return fmt.Errorf("copying file: %w", err)
	}

	_ = os.Chmod(tempFile.Name(), 0666)

	return nil
}

func getExponentialBackOff(elapsedTime time.Duration) *backoff.ExponentialBackOff {
	var (
		initialInterval     = 10 * time.Second
		randomizationFactor = 0.5
		multiplier          = 2.0
		maxInterval         = 30 * time.Second
		maxElapsedTime      = elapsedTime
	)

	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = initialInterval
	exp.RandomizationFactor = randomizationFactor
	exp.Multiplier = multiplier
	exp.MaxInterval = maxInterval
	exp.MaxElapsedTime = maxElapsedTime

	return exp
}

func (aac *ArtifactSnapshotClient) createAndPerformRequest(ctx context.Context, URL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		err = fmt.Errorf("composing request: %w", err)
		return nil, err
	}

	resp, err := aac.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing http request %v: %w", req, err)
	}

	return resp, nil
}
