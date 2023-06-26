// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	cannedVersions = `
	{
		"versions": [
		  "7.17.9",
		  "7.17.10",
		  "7.17.11-SNAPSHOT",
		  "8.6.0",
		  "8.6.1",
		  "8.6.2",
		  "8.7.0",
		  "8.7.1-SNAPSHOT",
		  "8.7.1",
		  "8.7.2-SNAPSHOT",
		  "8.8.0-SNAPSHOT",
		  "8.8.0",
		  "8.8.1-SNAPSHOT",
		  "8.9.0-SNAPSHOT"
		],
		"aliases": [
		  "7.17-SNAPSHOT",
		  "7.17",
		  "8.6",
		  "8.7-SNAPSHOT",
		  "8.7",
		  "8.8-SNAPSHOT",
		  "8.8",
		  "8.9-SNAPSHOT"
		],
		"manifests": {
		  "last-update-time": "Thu, 01 Jun 2023 07:50:21 UTC",
		  "seconds-since-last-update": 78
		}
	  }
	`
	// simplified response for version 8.9.0-SNAPSHOT
	cannedBuildVersions = `{
		"builds": [
		  "8.9.0-1ee08db3",
		  "8.9.0-f1fa1d73",
		  "8.9.0-3b0166e4",
		  "8.9.0-b4e26cd0",
		  "8.9.0-3cc641a9"
		],
		"manifests": {
		  "last-update-time": "Thu, 01 Jun 2023 08:31:02 UTC",
		  "seconds-since-last-update": 284
		}
	  }
	`
	// simplified response for build 8.9.0-SNAPSHOT+1ee08db3 (the original one is over 6k lines)
	cannedBuildDetails = `
	{
		"build": {
		  "projects": {
			"elastic-agent": {
			  "branch": "main",
			  "commit_hash": "a35c4986baf59970963b1027d9d5f8c06e24457c",
			  "commit_url": "https://github.com/elastic/elastic-agent/commits/a35c4986baf59970963b1027d9d5f8c06e24457c",
			  "build_duration_seconds": 3319,
			  "packages": {
				"elastic-agent-cloud-8.9.0-SNAPSHOT-docker-image-linux-amd64.tar.gz": {
				  "url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-cloud-8.9.0-SNAPSHOT-docker-image-linux-amd64.tar.gz",
				  "sha_url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-cloud-8.9.0-SNAPSHOT-docker-image-linux-amd64.tar.gz.sha512",
				  "asc_url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-cloud-8.9.0-SNAPSHOT-docker-image-linux-amd64.tar.gz.asc",
				  "type": "docker",
				  "architecture": "amd64",
				  "os": [
					"linux"
				  ],
				  "classifier": "docker-image",
				  "attributes": {
					"artifactNoKpi": "true",
					"internal": "false",
					"org": "beats-ci",
					"url": "docker.elastic.co/beats-ci/elastic-agent-cloud",
					"repo": "docker.elastic.co"
				  }
				},
				"elastic-agent-8.9.0-SNAPSHOT-arm64.deb": {
				  "url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-arm64.deb",
				  "sha_url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-arm64.deb.sha512",
				  "asc_url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-arm64.deb.asc",
				  "type": "deb",
				  "architecture": "arm64",
				  "attributes": {
					"include_in_repo": "true",
					"oss": "false"
				  }
				},
				"elastic-agent-8.9.0-SNAPSHOT-linux-x86_64.tar.gz": {
				  "url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-linux-x86_64.tar.gz",
				  "sha_url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-linux-x86_64.tar.gz.sha512",
				  "asc_url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-linux-x86_64.tar.gz.asc",
				  "type": "tar",
				  "architecture": "x86_64",
				  "os": [
					"linux"
				  ]
				},
				"elastic-agent-8.9.0-SNAPSHOT-windows-x86_64.zip": {
				  "url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-windows-x86_64.zip",
				  "sha_url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-windows-x86_64.zip.sha512",
				  "asc_url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-windows-x86_64.zip.asc",
				  "type": "zip",
				  "architecture": "x86_64",
				  "os": [
					"windows"
				  ]
				},
				"elastic-agent-8.9.0-SNAPSHOT-aarch64.rpm": {
				  "url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-aarch64.rpm",
				  "sha_url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-aarch64.rpm.sha512",
				  "asc_url": "https://snapshots.elastic.co/8.9.0-1ee08db3/downloads/beats/elastic-agent/elastic-agent-8.9.0-SNAPSHOT-aarch64.rpm.asc",
				  "type": "rpm",
				  "architecture": "aarch64",
				  "attributes": {
					"include_in_repo": "true",
					"oss": "false"
				  }
				}
			  },
			  "dependencies": []
			}
		  },
		  "start_time": "Thu, 1 Jun 2023 00:17:37 GMT",
		  "release_branch": "master",
		  "prefix": "",
		  "end_time": "Thu, 1 Jun 2023 04:20:22 GMT",
		  "manifest_version": "2.1.0",
		  "version": "8.9.0-SNAPSHOT",
		  "branch": "master",
		  "build_id": "8.9.0-1ee08db3",
		  "build_duration_seconds": 14565
		},
		"manifests": {
		  "last-update-time": "Thu, 01 Jun 2023 08:36:07 UTC",
		  "seconds-since-last-update": 208
		}
	  }
	`
)

func TestDefaultArtifactAPIClientErrorHttpStatus(t *testing.T) {

	httpErrorCodes := []int{
		http.StatusBadRequest,
		http.StatusNotFound,
		http.StatusForbidden,
		http.StatusTeapot,
		http.StatusInternalServerError,
	}

	for _, httpErrorCode := range httpErrorCodes {
		t.Run(fmt.Sprintf("HTTPCode%d", httpErrorCode), func(t *testing.T) {

			errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(httpErrorCode)
			})
			testSrv := httptest.NewServer(errorHandler)
			defer testSrv.Close()

			aac := NewArtifactAPIClient(WithUrl(testSrv.URL))
			_, err := aac.GetVersions(context.Background())
			assert.ErrorIs(t, err, ErrBadHTTPStatusCode, "Expected ErrBadHTTPStatusCode for status code %d", httpErrorCode)
			_, err = aac.GetBuildsForVersion(context.Background(), "1.2.3-SNAPSHOT")
			assert.ErrorIs(t, err, ErrBadHTTPStatusCode, "Expected ErrBadHTTPStatusCode for status code %d", httpErrorCode)
			_, err = aac.GetBuildDetails(context.Background(), "1.2.3", "abcdefg")
			assert.ErrorIs(t, err, ErrBadHTTPStatusCode, "Expected ErrBadHTTPStatusCode for status code %d", httpErrorCode)
		})
	}
}

func TestDefaultArtifactAPIClient(t *testing.T) {

	cannedRespHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Handling request %s", r.URL)
		switch r.URL.Path {
		case "/v1/versions/":
			_, _ = w.Write([]byte(cannedVersions))
		case "/v1/versions/8.9.0-SNAPSHOT/builds/":
			_, _ = w.Write([]byte(cannedBuildVersions))
		case "/v1/versions/8.9.0-SNAPSHOT/builds/8.9.0-1ee08db3":
			_, _ = w.Write([]byte(cannedBuildDetails))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	testSrv := httptest.NewServer(cannedRespHandler)
	defer testSrv.Close()

	aac := NewArtifactAPIClient(WithUrl(testSrv.URL))
	versions, err := aac.GetVersions(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, versions)
	assert.NotEmpty(t, versions.Versions)

	builds, err := aac.GetBuildsForVersion(context.Background(), "8.9.0-SNAPSHOT")
	assert.NoError(t, err)
	assert.NotNil(t, builds)
	assert.NotEmpty(t, builds.Builds)

	buildDetails, err := aac.GetBuildDetails(context.Background(), "8.9.0-SNAPSHOT", "8.9.0-1ee08db3")
	assert.NoError(t, err)
	assert.NotNil(t, buildDetails)
	assert.NotEmpty(t, buildDetails.Build)
	assert.NotEmpty(t, buildDetails.Build.Projects)
	assert.Contains(t, buildDetails.Build.Projects, "elastic-agent")
}
