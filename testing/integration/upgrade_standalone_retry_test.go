// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneUpgradeRetryDownload(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)
	startFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)
	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err, "failed to get end agent build version info")

	// Upgrade to an older snapshot build of same version but with a different commit hash
	aac := tools.NewArtifactAPIClient()
	buildInfo, err := aac.FindBuild(ctx, startVersion.VersionWithPrerelease(), startVersionInfo.Binary.Commit, 0)
	if errors.Is(err, tools.ErrBuildNotFound) {
		t.Skipf("there is no other build with a non-matching commit hash in the given version %s", define.Version())
		return
	}
	require.NoError(t, err)

	t.Logf("found build %q available for testing", buildInfo.Build.BuildID)
	endVersion := versionWithBuildID(t, startVersion, buildInfo.Build.BuildID)
	endFixture, err := atesting.NewFixture(
		t,
		endVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	// uses an internal http server that returns bad requests
	// until it returns a successful request
	srcPackage, err := endFixture.SrcPackage(ctx)
	require.NoError(t, err)

	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	count := 0
	fs := http.FileServer(http.Dir(filepath.Dir(srcPackage)))
	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		// fix path to remove '/beats/elastic-agent/' prefix
		upath := r.URL.Path
		if !strings.HasPrefix(upath, "/") {
			upath = "/" + upath
		}
		if strings.HasPrefix(upath, "/beats/elastic-agent/") {
			upath = strings.TrimPrefix(upath, "/beats/elastic-agent/")
		}
		r.URL.Path = upath

		if path.Base(r.URL.Path) == filepath.Base(srcPackage) && count < 2 {
			// first 2 requests return 404
			count += 1
			t.Logf("request #%d; returning not found", count)
			rw.WriteHeader(http.StatusNotFound)
			return
		}

		fs.ServeHTTP(rw, r)
	})

	go func() {
		_ = http.Serve(l, handler)
	}()

	sourceURI := fmt.Sprintf("http://localhost:%d", port)
	err = upgradetest.PerformUpgrade(
		ctx, startFixture, endFixture, t, upgradetest.WithSourceURI(sourceURI))
	assert.NoError(t, err)
	assert.Equal(t, 2, count, "retry request didn't occur")
}
