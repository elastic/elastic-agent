// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package snapshots

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/version"
)

var branchList = []string{
	"master",
	"8.13",
	"8.12",
	"8.11",
	"8.10",
	"7.17",
}

func TestFindLatestSnapshots(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// real responses from https://snapshots.elastic.co
	existingSnapshots := map[string]string{
		"/latest/master.json": `{"version":"8.14.0-SNAPSHOT","build_id":"8.14.0-3c66177b","manifest_url":"https://snapshots.elastic.co/8.14.0-3c66177b/manifest-8.14.0-SNAPSHOT.json","summary_url":"https://snapshots.elastic.co/8.14.0-3c66177b/summary-8.14.0-SNAPSHOT.html"}`,
		"/latest/8.13.json":   `{"version":"8.13.0-SNAPSHOT","build_id":"8.13.0-18e35b5c","manifest_url":"https://snapshots.elastic.co/8.13.0-18e35b5c/manifest-8.13.0-SNAPSHOT.json","summary_url":"https://snapshots.elastic.co/8.13.0-18e35b5c/summary-8.13.0-SNAPSHOT.html"}`,
		"/latest/8.12.json":   `{"version":"8.12.3-SNAPSHOT","build_id":"8.12.3-38b17954","manifest_url":"https://snapshots.elastic.co/8.12.3-38b17954/manifest-8.12.3-SNAPSHOT.json","summary_url":"https://snapshots.elastic.co/8.12.3-38b17954/summary-8.12.3-SNAPSHOT.html"}`,
		"/latest/7.17.json":   `{"version":"7.17.19-SNAPSHOT","build_id":"7.17.19-a2ab9cd7","manifest_url":"https://snapshots.elastic.co/7.17.19-a2ab9cd7/manifest-7.17.19-SNAPSHOT.json","summary_url":"https://snapshots.elastic.co/7.17.19-a2ab9cd7/summary-7.17.19-SNAPSHOT.html"}`,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, exists := existingSnapshots[r.URL.Path]
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		written, err := w.Write([]byte(v))
		assert.NoError(t, err)
		assert.Equal(t, len(v), written)
	}))

	sc := NewSnapshotsClient(WithUrl(server.URL))
	versions, err := sc.FindLatestSnapshots(ctx, branchList)
	require.NoError(t, err)
	assert.NotEmpty(t, versions)

	expectedVersions := parseVersions(t, []string{
		"8.14.0-SNAPSHOT",
		"8.13.0-SNAPSHOT",
		"8.12.3-SNAPSHOT",
		"7.17.19-SNAPSHOT",
	})
	assert.Equal(t, expectedVersions, versions)
}

// parseVersions returns a prepared list of versions that should match the `FetchAgentVersions` output
func parseVersions(t *testing.T, versions []string) version.SortableParsedVersions {
	expectedVersions := make(version.SortableParsedVersions, 0, len(versions))
	for _, v := range versions {
		parsed, err := version.ParseVersion(v)
		require.NoError(t, err)
		expectedVersions = append(expectedVersions, parsed)
	}

	return expectedVersions
}
