// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgradetest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/version"
	bversion "github.com/elastic/elastic-agent/version"
)

// Response from https://artifacts-api.elastic.co/v1/versions
var versionsResponse = tools.VersionList{
	Versions: []string{
		"7.17.13",
		"7.17.14",
		"7.17.15",
		"7.17.16",
		"7.17.17",
		"7.17.18-SNAPSHOT",
		"7.17.18",
		"7.17.19-SNAPSHOT",
		"8.9.2",
		"8.10.0",
		"8.10.1",
		"8.10.2",
		"8.10.3",
		"8.10.4",
		"8.11.0",
		"8.11.1",
		"8.11.2",
		"8.11.3",
		"8.11.4",
		"8.12.0",
		"8.12.1-SNAPSHOT",
		"8.12.1",
		"8.12.2-SNAPSHOT",
		"8.12.2",
		"8.13.0-SNAPSHOT",
		"8.13.0",
		"8.14.0-SNAPSHOT",
	},
	Aliases: []string{
		"7.17-SNAPSHOT",
		"7.17",
		"8.9",
		"8.10",
		"8.11",
		"8.12-SNAPSHOT",
		"8.12",
		"8.13-SNAPSHOT",
		"8.13",
		"8.14-SNAPSHOT",
	},
	Manifests: tools.Manifests{
		LastUpdateTime:         "Fri, 23 Feb 2024 11:25:33 UTC",
		SecondsSinceLastUpdate: 164,
	},
}

func TestFetchUpgradableVersionsAfterFeatureFreeze(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	expectedUpgradableVersions := []string{
		"8.13.0-SNAPSHOT",
		"8.12.2",
		"8.12.2-SNAPSHOT",
		"8.12.1",
		"8.12.0",
		"8.11.4",
		"7.17.18",
	}

	versionBytes, err := json.Marshal(versionsResponse)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(http.StatusOK)
		_, err := io.Copy(resp, bytes.NewBuffer(versionBytes))
		assert.NoError(t, err)
	}))
	defer server.Close()
	aac := tools.NewArtifactAPIClient(tools.WithUrl(server.URL), tools.WithLogFunc(t.Logf))

	reqs := VersionRequirements{
		UpgradeToVersion: "8.13.0", // to test that 8.14 is not returned
		CurrentMajors:    3,        // should return 8.12.2, 8.12.1, 8.12.0
		PreviousMajors:   3,        // should return 7.17.18
		PreviousMinors:   2,        // should return 8.12.2, 8.11.4
		RecentSnapshots:  2,        // should return 8.13.0-SNAPSHOT, 8.12.2-SNAPSHOT
	}
	versions, err := FetchUpgradableVersions(ctx, aac, reqs)
	require.NoError(t, err)
	assert.Equal(t, expectedUpgradableVersions, versions)
}

func TestGetUpgradableVersions(t *testing.T) {
	versions, err := GetUpgradableVersions()
	require.NoError(t, err)
	assert.Truef(t, len(versions) > 1, "expected at least one version for testing, got %d.\n%v", len(versions), versions)
}

func TestPreviousMinor(t *testing.T) {
	currentParsed, err := version.ParseVersion(bversion.Agent)
	require.NoError(t, err)

	v, err := PreviousMinor()
	require.NoError(t, err)

	parsed, err := version.ParseVersion(v)
	require.NoError(t, err)
	assert.Truef(t, currentParsed.Major() == parsed.Major() && currentParsed.Minor() > parsed.Minor(), "%s is not previous minor for %s", v, bversion.Agent)
	assert.Empty(t, parsed.Prerelease())
	assert.Empty(t, parsed.BuildMetadata())
}
