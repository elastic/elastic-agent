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
	// simplified response for version 8.9.0-SNAPSHOT
	cannedBuildVersions = `{
		"builds": [
		  "8.9.0-abcdefgh",
		  "8.9.0-12343567",
		  "8.9.0-asdfasds"
		],
		"manifests": {
		  "last-update-time": "Thu, 01 Jun 2023 08:31:02 UTC",
		  "seconds-since-last-update": 284
		}
	}
	`
	// simplified response for build 8.9.0-SNAPSHOT+abcdefgh (the original one is over 6k lines)
	cannedBuildDetails1 = `
	{
		"build": {
		  "projects": {
			"elastic-agent-package": {
			  "branch": "main",
			  "commit_hash": "a35c4986baf59970963b1027d9d5f8c06e24457c",
			  "commit_url": "https://github.com/elastic/elastic-agent/commits/a35c4986baf59970963b1027d9d5f8c06e24457c",
			  "build_duration_seconds": 3319
			}
		  },
		  "start_time": "Thu, 1 Jun 2023 00:17:37 GMT",
		  "release_branch": "master",
		  "prefix": "",
		  "end_time": "Thu, 1 Jun 2023 04:20:22 GMT",
		  "manifest_version": "2.1.0",
		  "version": "8.9.0-SNAPSHOT",
		  "branch": "master",
		  "build_id": "8.9.0-abcdefgh",
		  "build_duration_seconds": 14565
		},
		"manifests": {
		  "last-update-time": "Thu, 01 Jun 2023 08:36:07 UTC",
		  "seconds-since-last-update": 208
		}
	}
	`
	cannedBuildDetails2 = `
	{
		"build": {
		  "projects": {
			  "elastic-agent-package": {
			    "branch": "main",
			    "commit_hash": "b35c4986baf59970963b1027d9d5f8c06e24457d",
			    "commit_url": "https://github.com/elastic/elastic-agent/commits/a35c4986baf59970963b1027d9d5f8c06e24457c"
		    }
		  },
		  "start_time": "Thu, 1 Jun 2023 00:17:37 GMT",
		  "release_branch": "master",
		  "prefix": "",
		  "end_time": "Thu, 1 Jun 2023 04:20:22 GMT",
		  "manifest_version": "2.1.0",
		  "version": "8.9.0-SNAPSHOT",
		  "branch": "master",
		  "build_id": "8.9.0-12343567",
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

			aac := NewArtifactAPIClient(WithUrl(testSrv.URL), WithLogFunc(t.Logf))
			_, err := aac.FindBuild(context.Background(), "1.2.3", "abcdefg", 0)
			assert.ErrorIs(t, err, ErrBadHTTPStatusCode, "Expected ErrBadHTTPStatusCode for status code %d", httpErrorCode)
		})
	}
}

func TestDefaultArtifactAPIClient(t *testing.T) {

	cannedRespHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Handling request %s", r.URL)
		switch r.URL.Path {
		case "/v1/versions/8.9.0-SNAPSHOT/builds/":
			_, _ = w.Write([]byte(cannedBuildVersions))
		case "/v1/versions/8.9.0-SNAPSHOT/builds/8.9.0-abcdefgh":
			_, _ = w.Write([]byte(cannedBuildDetails1))
		case "/v1/versions/8.9.0-SNAPSHOT/builds/8.9.0-12343567":
			_, _ = w.Write([]byte(cannedBuildDetails2))
		case "/v1/versions/8.9.0-SNAPSHOT/builds/8.9.0-asdfasds":
			// re-use the second details here because it does not matter if
			// it's different in all the test-cases below
			_, _ = w.Write([]byte(cannedBuildDetails2))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	testSrv := httptest.NewServer(cannedRespHandler)
	defer testSrv.Close()

	aac := NewArtifactAPIClient(WithUrl(testSrv.URL), WithLogFunc(t.Logf))

	t.Run("returns the latest", func(t *testing.T) {
		expBuildID := "8.9.0-abcdefgh"
		build, err := aac.FindBuild(context.Background(), "8.9.0-SNAPSHOT", "", 0)
		assert.NoError(t, err)
		assert.NotNil(t, build)
		assert.Equal(t, expBuildID, build.Build.BuildID)
	})

	t.Run("returns offset 1", func(t *testing.T) {
		expBuildID := "8.9.0-12343567"
		build, err := aac.FindBuild(context.Background(), "8.9.0-SNAPSHOT", "", 1)
		assert.NoError(t, err)
		assert.NotNil(t, build)
		assert.Equal(t, expBuildID, build.Build.BuildID)
	})

	t.Run("returns no excluded hash", func(t *testing.T) {
		excludeHash := "a35c4986baf59970963b1027d9d5f8c06e24457c"
		expBuildID := "8.9.0-12343567"
		build, err := aac.FindBuild(context.Background(), "8.9.0-SNAPSHOT", excludeHash, 0)
		assert.NoError(t, err)
		assert.NotNil(t, build)
		assert.Equal(t, expBuildID, build.Build.BuildID)
	})

	t.Run("returns ErrBuildNotFound when offset and matching excluded hash", func(t *testing.T) {
		excludeHash := "b35c4986baf59970963b1027d9d5f8c06e24457d"
		build, err := aac.FindBuild(context.Background(), "8.9.0-SNAPSHOT", excludeHash, 1)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrBuildNotFound)
		assert.Nil(t, build)
	})
}
