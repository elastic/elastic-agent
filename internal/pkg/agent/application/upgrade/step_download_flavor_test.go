// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"crypto/sha512"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/internal/pkg/testutils/fipsutils"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/pgptest"
)

// TestNewAgentArtifactUsesBuildFlavor verifies that the artifact an agent upgrades to carries
// the flavor stamped into the running binary. Run it with
// -ldflags "-X github.com/elastic/elastic-agent/internal/pkg/release.flavor=edr" to cover an
// edr build.
func TestNewAgentArtifactUsesBuildFlavor(t *testing.T) {
	target, err := newAgentArtifact(agtversion.NewParsedSemVer(9, 6, 0, "", ""))
	require.NoError(t, err)

	t.Logf("build flavor %q, artifact %s", release.Flavor(), target.FileName())
	assert.Equal(t, release.Flavor(), target.Flavor)
	if release.Flavor() == "" {
		assert.True(t, strings.HasPrefix(target.FileName(), "elastic-agent-9.6.0-"), target.FileName())
		return
	}
	assert.True(t, strings.HasPrefix(target.FileName(), "elastic-agent-"+release.Flavor()+"-9.6.0-"), target.FileName())
}

// TestDownloadArtifactOnlyUsesOwnFlavor verifies that an agent of a dedicated flavor only ever
// fetches artifacts of that flavor, even when an artifact of another flavor is available from
// the same source.
func TestDownloadArtifactOnlyUsesOwnFlavor(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "test uses an OpenPGP key which results in a SHA-1 violation")

	originalDownloads := paths.Downloads()
	t.Cleanup(func() { paths.SetDownloads(originalDownloads) })

	version := agtversion.NewParsedSemVer(1, 2, 3, "", "")

	type artifactFiles struct {
		name      string
		content   []byte
		hash      []byte
		signature []byte
	}
	var pgpSource string
	newArtifactFiles := func(t *testing.T, flavor string, content string) artifactFiles {
		t.Helper()
		target, err := artifact.New("elastic-agent", flavor, false, version, "linux", "amd64")
		require.NoError(t, err)
		data := []byte(content)
		key, signature := pgptest.Sign(t, strings.NewReader(content))
		pgpSource = download.PgpSourceRawPrefix + string(key)
		return artifactFiles{
			name:      target.FileName(),
			content:   data,
			hash:      []byte(fmt.Sprintf("%x %s", sha512.Sum512(data), target.FileName())),
			signature: signature,
		}
	}

	newDownloader := func(t *testing.T) *artifactDownloader {
		t.Helper()
		paths.SetDownloads(filepath.Join(t.TempDir(), "downloads"))
		settings := &artifact.Config{
			TargetDirectory:        paths.Downloads(),
			RetrySleepInitDuration: time.Millisecond,
			HTTPTransportSettings:  httpcommon.HTTPTransportSettings{Timeout: time.Second},
		}
		log, _ := loggertest.New(t.Name())
		downloader := newArtifactDownloader(settings, log)
		downloader.getPGPSources = func(_ *logger.Logger, _ string, _ *agtversion.ParsedSemVer, pgpSources []string) []string {
			return pgpSources
		}
		return downloader
	}

	writeToDir := func(t *testing.T, dir string, files artifactFiles) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, files.name), files.content, 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, files.name+".sha512"), files.hash, 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, files.name+".asc"), files.signature, 0o644))
	}

	edrTarget, err := artifact.New("elastic-agent", release.FlavorEDR, false, version, "linux", "amd64")
	require.NoError(t, err)
	standardTarget, err := artifact.New("elastic-agent", "", false, version, "linux", "amd64")
	require.NoError(t, err)

	t.Run("edr agent does not use a standard artifact from a local source", func(t *testing.T) {
		downloader := newDownloader(t)
		standard := newArtifactFiles(t, "", "standard artifact")
		dropPath := t.TempDir()
		writeToDir(t, dropPath, standard)

		_, err := downloader.downloadArtifact(t.Context(), edrTarget, []string{"file://" + dropPath},
			details.NewDetails(version.String(), details.StateRequested, ""), false, true, pgpSource)
		require.ErrorContains(t, err, "could not fetch artifact")
		require.NoFileExists(t, filepath.Join(paths.Downloads(), standard.name))
		require.NoFileExists(t, filepath.Join(paths.Downloads(), edrTarget.FileName()+".sha512"))
	})

	t.Run("edr agent picks the edr artifact when both are available locally", func(t *testing.T) {
		downloader := newDownloader(t)
		standard := newArtifactFiles(t, "", "standard artifact")
		edr := newArtifactFiles(t, release.FlavorEDR, "edr artifact")
		dropPath := t.TempDir()
		writeToDir(t, dropPath, standard)
		writeToDir(t, dropPath, edr)

		archivePath, err := downloader.downloadArtifact(t.Context(), edrTarget, []string{"file://" + dropPath},
			details.NewDetails(version.String(), details.StateRequested, ""), false, true, pgpSource)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(paths.Downloads(), edr.name), archivePath)
		got, err := os.ReadFile(archivePath)
		require.NoError(t, err)
		require.Equal(t, edr.content, got)
		require.NoFileExists(t, filepath.Join(paths.Downloads(), standard.name))
	})

	t.Run("edr agent only requests edr artifacts from a remote source", func(t *testing.T) {
		downloader := newDownloader(t)
		standard := newArtifactFiles(t, "", "standard artifact")
		edr := newArtifactFiles(t, release.FlavorEDR, "edr artifact")
		files := map[string][]byte{}
		for _, a := range []artifactFiles{standard, edr} {
			base := "/beats/elastic-agent/" + a.name
			files[base] = a.content
			files[base+".sha512"] = a.hash
			files[base+".asc"] = a.signature
		}
		var requested []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requested = append(requested, r.URL.Path)
			file, ok := files[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(file)
		}))
		t.Cleanup(server.Close)

		archivePath, err := downloader.downloadArtifact(t.Context(), edrTarget, []string{server.URL},
			details.NewDetails(version.String(), details.StateRequested, ""), false, true, pgpSource)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(paths.Downloads(), edr.name), archivePath)
		require.NotEmpty(t, requested)
		for _, path := range requested {
			assert.Contains(t, path, "elastic-agent-edr-", "request for a non-edr artifact: %s", path)
		}
	})

	t.Run("standard agent does not use an edr artifact", func(t *testing.T) {
		downloader := newDownloader(t)
		edr := newArtifactFiles(t, release.FlavorEDR, "edr artifact")
		dropPath := t.TempDir()
		writeToDir(t, dropPath, edr)

		_, err := downloader.downloadArtifact(t.Context(), standardTarget, []string{"file://" + dropPath},
			details.NewDetails(version.String(), details.StateRequested, ""), false, true, pgpSource)
		require.ErrorContains(t, err, "could not fetch artifact")
		require.NoFileExists(t, filepath.Join(paths.Downloads(), edr.name))
	})
}
