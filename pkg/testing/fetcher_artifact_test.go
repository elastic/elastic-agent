// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArtifactFetcher_Name(t *testing.T) {
	f := ArtifactFetcher()
	require.Equal(t, "artifact", f.Name())
}

func TestArtifactFetcher_Default(t *testing.T) {
	f := ArtifactFetcher()
	af := f.(*artifactFetcher)
	af.doer = newFakeHttpClient(t)

	tmp := t.TempDir()
	res, err := f.Fetch(context.Background(), "linux", "amd64", "8.12.0", "targz")
	require.NoError(t, err)

	err = res.Fetch(context.Background(), t, tmp)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmp, res.Name()))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmp, res.Name()+extHash))
	require.NoError(t, err)
}

func TestArtifactFetcher_Snapshot(t *testing.T) {
	f := ArtifactFetcher()
	af := f.(*artifactFetcher)
	af.doer = newFakeHttpClient(t)

	tmp := t.TempDir()
	res, err := f.Fetch(context.Background(), "linux", "amd64", "8.13.0-SNAPSHOT", "targz")
	require.NoError(t, err)

	err = res.Fetch(context.Background(), t, tmp)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmp, res.Name()))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmp, res.Name()+extHash))
	require.NoError(t, err)
	assert.Contains(t, res.Name(), "-SNAPSHOT")
}

func TestArtifactFetcher_SnapshotOnly(t *testing.T) {
	f := ArtifactFetcher(WithArtifactSnapshotOnly())
	af := f.(*artifactFetcher)
	af.doer = newFakeHttpClient(t)

	tmp := t.TempDir()
	res, err := f.Fetch(context.Background(), "linux", "amd64", "8.13.0", "targz")
	require.NoError(t, err)

	err = res.Fetch(context.Background(), t, tmp)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmp, res.Name()))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmp, res.Name()+extHash))
	require.NoError(t, err)
	assert.Contains(t, res.Name(), "-SNAPSHOT")
}

func TestArtifactFetcher_Build(t *testing.T) {
	f := ArtifactFetcher()
	af := f.(*artifactFetcher)
	af.doer = newFakeHttpClient(t)

	tmp := t.TempDir()
	res, err := f.Fetch(context.Background(), "linux", "amd64", "8.13.0-SNAPSHOT+l5snflwr", "targz")
	require.NoError(t, err)

	err = res.Fetch(context.Background(), t, tmp)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmp, res.Name()))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmp, res.Name()+extHash))
	require.NoError(t, err)
	assert.Contains(t, res.Name(), "-SNAPSHOT")
	assert.Contains(t, res.Name(), "l5snflwr")
}

type fakeHttpClient struct {
	responses map[string]*http.Response
}

func (c *fakeHttpClient) Do(req *http.Request) (*http.Response, error) {
	urlString := req.URL.String()
	resp := c.responses[urlString]
	if resp == nil {
		return nil, fmt.Errorf("unexpected URL %q", urlString)
	}
	return resp, nil
}

func newFakeHttpClient(t *testing.T) *fakeHttpClient {
	releaseResponse, err := os.ReadFile("./testdata/release-response.json")
	require.NoError(t, err)

	snapshotResponse, err := os.ReadFile("./testdata/snapshot-response.json")
	require.NoError(t, err)

	manifestResponse, err := os.ReadFile("./testdata/build-manifest.json")
	require.NoError(t, err)

	binaryResponse := "not valid data; but its very fast to download something this small"
	hashResponse := "c2f59774022b79b61a7e6bbe28f3388d00a5bc2c7416a5c8fda79042af491d335f9b87adf905d1b154abdd2e31b200e4b1bb23cb472297596b25edef0a3b8d59"
	ascResponse := `-----BEGIN PGP SIGNATURE-----

        wsBcBAABCAAQBQJlTLh5CRD2Vuvax5DnywAAzNcIADKuYov0CMeK938JQEzR4mXP
        BoYB7Zz/IkN7A5mMztRnHi1eglr2/begM22AmC5L55OsYG5orNWV83MQPeKIr5Ub
        9gy/BktLAQTePNH6QvRzJKE3LR1pI2TT39svILoOjnPkovH/7ssa6X+/WcNE1/jX
        i7St7ZCDRZgDcmWtln7feDcYT7MdMUaQn+WP97KKbwIBTh9kOkHq9ycXnC6qT0/3
        GZT9xXTpBjctewSFja4RNCq8cmZGI2iILzFERH6MSD0iOuBV5cYKOgf/ZWtWGvad
        BuQTKP/NxCDmqhnEmJQi7BSP2UPNp+6/G8a38IyC/jlJs/f46fj+lpvQt3yn924=
        =fhCM
        -----END PGP SIGNATURE-----`
	return &fakeHttpClient{responses: map[string]*http.Response{
		// searching for a release version
		"https://artifacts-api.elastic.co/v1/search/8.12.0/elastic-agent": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(releaseResponse)),
		},

		// searching for a snapshot
		"https://artifacts-api.elastic.co/v1/search/8.13.0-SNAPSHOT/elastic-agent": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(snapshotResponse)),
		},

		// fetching the build
		"https://snapshots.elastic.co/8.13.0-l5snflwr/manifest-8.13.0-SNAPSHOT.json": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(manifestResponse)),
		},

		// actual artifacts
		// 8.12 release
		"https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.12.0-linux-x86_64.tar.gz": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(binaryResponse))),
		},
		"https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.12.0-linux-x86_64.tar.gz.sha512": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(hashResponse))),
		},
		"https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.12.0-linux-x86_64.tar.gz.asc": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(ascResponse))),
		},
		// 8.13 SNAPSHOT
		"https://snapshots.elastic.co/8.13.0-yil7wib0/downloads/beats/elastic-agent/elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(binaryResponse))),
		},
		"https://snapshots.elastic.co/8.13.0-yil7wib0/downloads/beats/elastic-agent/elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz.sha512": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(hashResponse))),
		},
		"https://snapshots.elastic.co/8.13.0-yil7wib0/downloads/beats/elastic-agent/elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz.asc": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(ascResponse))),
		},
		"https://snapshots.elastic.co/latest/8.13.0-SNAPSHOT.json": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"build_id":"8.13.0-yil7wib0"}`))),
		},

		// 8.13 build l5snflwr
		"https://snapshots.elastic.co/8.13.0-l5snflwr/downloads/beats/elastic-agent/elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(binaryResponse))),
		},
		"https://snapshots.elastic.co/8.13.0-l5snflwr/downloads/beats/elastic-agent/elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz.sha512": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(hashResponse))),
		},
		"https://snapshots.elastic.co/8.13.0-l5snflwr/downloads/beats/elastic-agent/elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz.asc": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(ascResponse))),
		},
	}}

}
