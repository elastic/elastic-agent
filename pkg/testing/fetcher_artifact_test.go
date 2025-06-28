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
	require.NoError(t, err, "failed to read release response")

	snapshotResponse, err := os.ReadFile("./testdata/snapshot-response.json")
	require.NoError(t, err, "failed to read snapshot response")

	manifestResponse, err := os.ReadFile("./testdata/build-manifest.json")
	require.NoError(t, err, "failed to read manifest response")

	binaryResponse, err := os.ReadFile("./testdata/data.tar.gz")
	require.NoError(t, err, "failed to read binary response")
	hashResponse := "cc52f8aa1106857dae8d380f6c2cf789d5d52730df0b0e6aba908a5e1f3cb947fda63bb4bc0301a3bc3329ef4b2f3c5fa9be9d8975a4d0f8f43076cfd5a5ec8a"
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
			Body:       io.NopCloser(bytes.NewReader(binaryResponse)),
		},
		"https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.12.0-linux-x86_64.tar.gz.sha512": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(hashResponse + " elastic-agent-8.12.0-linux-x86_64.tar.gz"))),
		},
		"https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.12.0-linux-x86_64.tar.gz.asc": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(ascResponse))),
		},
		// 8.13 SNAPSHOT
		"https://snapshots.elastic.co/8.13.0-yil7wib0/downloads/beats/elastic-agent/elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(binaryResponse)),
		},
		"https://snapshots.elastic.co/8.13.0-yil7wib0/downloads/beats/elastic-agent/elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz.sha512": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(hashResponse + " elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz"))),
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
			Body:       io.NopCloser(bytes.NewReader(binaryResponse)),
		},
		"https://snapshots.elastic.co/8.13.0-l5snflwr/downloads/beats/elastic-agent/elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz.sha512": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(hashResponse + " elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz"))),
		},
		"https://snapshots.elastic.co/8.13.0-l5snflwr/downloads/beats/elastic-agent/elastic-agent-8.13.0-SNAPSHOT-linux-x86_64.tar.gz.asc": {
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(ascResponse))),
		},
	}}

}
