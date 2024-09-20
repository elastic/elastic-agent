// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package product_versions

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/version"
)

func TestFetchAgentVersions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	versionResponse, err := os.ReadFile("./testdata/versions.json")
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/product_versions" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		written, err := w.Write(versionResponse)
		assert.NoError(t, err)
		assert.Equal(t, len(versionResponse), written)
	}))
	pvc := NewProductVersionsClient(WithUrl(server.URL))

	versions, err := pvc.FetchAgentVersions(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, versions)
	expectedVersions := readExpectedVersions(t)
	assert.NotEmpty(t, expectedVersions)
	assert.Equal(t, expectedVersions, versions)
}

// readExpectedVersions returns a prepared list of versions that should match the `FetchAgentVersions` output
func readExpectedVersions(t *testing.T) version.SortableParsedVersions {
	var expectedVersions version.SortableParsedVersions
	expectedVersionsFile, err := os.Open("./testdata/expected-versions.txt")
	require.NoError(t, err)
	defer expectedVersionsFile.Close()

	scanner := bufio.NewScanner(expectedVersionsFile)
	for scanner.Scan() {
		v, err := version.ParseVersion(scanner.Text())
		require.NoError(t, err)
		expectedVersions = append(expectedVersions, v)
	}
	require.NoError(t, scanner.Err())

	return expectedVersions
}
