// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"io"
	"net"
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
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/testutils/fipsutils"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/pgptest"
)

func TestDownloadArtifact(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "test uses an OpenPGP key which results in a SHA-1 violation")

	originalDownloads := paths.Downloads()
	t.Cleanup(func() {
		paths.SetDownloads(originalDownloads)
	})

	archiveContent := []byte("signed artifact content")
	pgpKey, signature := pgptest.Sign(t, bytes.NewReader(archiveContent))
	pgpSource := download.PgpSourceRawPrefix + string(pgpKey)
	hashFile := []byte(fmt.Sprintf("%x %s", sha512.Sum512(archiveContent), "elastic-agent-1.2.3-linux-x86_64.tar.gz"))

	requestCountHandler := func(files map[string][]byte, requestCounts map[string]int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			requestCounts[path]++

			file, ok := files[path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			_, _ = w.Write(file)
		}
	}

	newFileServer := func(t *testing.T, files map[string][]byte) (string, map[string]int) {
		t.Helper()
		requestCounts := map[string]int{}
		server := httptest.NewServer(requestCountHandler(files, requestCounts))
		t.Cleanup(server.Close)
		return server.URL, requestCounts
	}

	type fixture struct {
		downloader     *artifactDownloader
		target         artifact.Artifact
		settings       *artifact.Config
		upgradeDetails *details.Details
	}

	tests := []struct {
		name    string
		version *agtversion.ParsedSemVer
		run     func(*testing.T, *fixture)
	}{
		{
			name: "local-only sourceURI copies from local source",
			run: func(t *testing.T, fx *fixture) {
				dropPath := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()), archiveContent, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()+".sha512"), hashFile, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()+".asc"), signature, 0o644))

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, "file://"+dropPath,
					fx.upgradeDetails, false, true, pgpSource)
				require.NoError(t, err)
				require.Equal(t, filepath.Join(paths.Downloads(), fx.target.FileName()), artifactPath)
				require.FileExists(t, artifactPath)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "local-only sourceURI fails when local artifact is missing",
			run: func(t *testing.T, fx *fixture) {
				serverURL, requestCounts := newFileServer(t, nil)
				fx.settings.SourceURI = serverURL

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, "file://"+t.TempDir(),
					fx.upgradeDetails, false, true, pgpSource)
				require.ErrorContains(t, err, "could not fetch artifact")
				require.Empty(t, requestCounts)
				require.NoFileExists(t, artifactPath)
				require.NoFileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "local-only sourceURI fails when local artifact is missing its hash",
			run: func(t *testing.T, fx *fixture) {
				dropPath := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()), archiveContent, 0o644))

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, "file://"+dropPath,
					fx.upgradeDetails, false, true, pgpSource)
				require.ErrorContains(t, err, "could not fetch artifact sha512")
				require.FileExists(t, artifactPath)
				require.NoFileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "local-only sourceURI fails when local verification fails",
			run: func(t *testing.T, fx *fixture) {
				dropPath := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()), archiveContent, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()+".sha512"), hashFile, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()+".asc"), []byte("not a valid signature"), 0o644))

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, "file://"+dropPath,
					fx.upgradeDetails, false, true, pgpSource)
				require.ErrorContains(t, err, "verification failed")
				require.FileExists(t, artifactPath)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "local-only sourceURI skips verification if skipVerify is set",
			run: func(t *testing.T, fx *fixture) {
				dropPath := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()), archiveContent, 0o644))

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, "file://"+dropPath,
					fx.upgradeDetails, true, true, pgpSource)
				require.NoError(t, err)
				require.FileExists(t, artifactPath)
				require.NoFileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "remote sourceURI uses remote source when drop path is unset",
			run: func(t *testing.T, fx *fixture) {
				remotePath := "/beats/elastic-agent/" + fx.target.FileName()
				serverURL, requestCounts := newFileServer(t, map[string][]byte{
					remotePath:             archiveContent,
					remotePath + ".sha512": hashFile,
					remotePath + ".asc":    signature,
				})

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, serverURL,
					fx.upgradeDetails, false, true, pgpSource)
				require.NoError(t, err)
				require.Equal(t, filepath.Join(paths.Downloads(), fx.target.FileName()), artifactPath)
				require.Equal(t, 1, requestCounts[remotePath])
				require.Equal(t, 1, requestCounts[remotePath+".sha512"])
				require.Equal(t, 1, requestCounts[remotePath+".asc"])
				require.FileExists(t, artifactPath)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "remote sourceURI fails when remote artifact is missing",
			run: func(t *testing.T, fx *fixture) {
				remotePath := "/beats/elastic-agent/" + fx.target.FileName()
				serverURL, requestCounts := newFileServer(t, nil)

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, serverURL,
					fx.upgradeDetails, false, true, pgpSource)
				require.ErrorContains(t, err, "could not fetch artifact from")
				require.Equal(t, 1, requestCounts[remotePath])
				require.Equal(t, 0, requestCounts[remotePath+".sha512"])
				require.NoFileExists(t, artifactPath)
				require.NoFileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "remote sourceURI fails when remote artifact is missing its hash",
			run: func(t *testing.T, fx *fixture) {
				remotePath := "/beats/elastic-agent/" + fx.target.FileName()
				serverURL, requestCounts := newFileServer(t, map[string][]byte{
					remotePath: archiveContent,
				})

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, serverURL,
					fx.upgradeDetails, false, true, pgpSource)
				require.ErrorContains(t, err, "could not fetch artifact sha512")
				require.Equal(t, 1, requestCounts[remotePath])
				require.Equal(t, 1, requestCounts[remotePath+".sha512"])
				require.FileExists(t, artifactPath)
				require.NoFileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "remote sourceURI fails when remote verification fails",
			run: func(t *testing.T, fx *fixture) {
				remotePath := "/beats/elastic-agent/" + fx.target.FileName()
				serverURL, requestCounts := newFileServer(t, map[string][]byte{
					remotePath:             archiveContent,
					remotePath + ".sha512": hashFile,
					remotePath + ".asc":    []byte("not a valid signature"),
				})

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, serverURL,
					fx.upgradeDetails, false, true, pgpSource)
				require.ErrorContains(t, err, "verification failed")
				require.Equal(t, 1, requestCounts[remotePath])
				require.Equal(t, 1, requestCounts[remotePath+".sha512"])
				require.Equal(t, 1, requestCounts[remotePath+".asc"])
				require.FileExists(t, artifactPath)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "remote sourceURI skips verification if skipVerify is set",
			run: func(t *testing.T, fx *fixture) {
				remotePath := "/beats/elastic-agent/" + fx.target.FileName()
				serverURL, requestCounts := newFileServer(t, map[string][]byte{
					remotePath: archiveContent,
				})

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, serverURL,
					fx.upgradeDetails, true, true, pgpSource)
				require.NoError(t, err)
				require.Equal(t, 1, requestCounts[remotePath])
				require.FileExists(t, artifactPath)
				require.NoFileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "remote sourceURI copies from local drop path if available",
			run: func(t *testing.T, fx *fixture) {
				dropPath := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()), archiveContent, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()+".sha512"), hashFile, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()+".asc"), signature, 0o644))
				fx.settings.DropPath = dropPath

				serverURL, requestCounts := newFileServer(t, nil)

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, serverURL,
					fx.upgradeDetails, false, true, pgpSource)
				require.NoError(t, err)
				require.Empty(t, requestCounts)
				require.FileExists(t, artifactPath)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "remote sourceURI uses remote source when drop path is set but artifact is missing",
			run: func(t *testing.T, fx *fixture) {
				fx.settings.DropPath = t.TempDir()

				remotePath := "/beats/elastic-agent/" + fx.target.FileName()
				serverURL, requestCounts := newFileServer(t, map[string][]byte{
					remotePath:             archiveContent,
					remotePath + ".sha512": hashFile,
					remotePath + ".asc":    signature,
				})

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, serverURL,
					fx.upgradeDetails, false, true, pgpSource)
				require.NoError(t, err)
				require.Equal(t, 1, requestCounts[remotePath])
				require.Equal(t, 1, requestCounts[remotePath+".sha512"])
				require.Equal(t, 1, requestCounts[remotePath+".asc"])
				require.FileExists(t, artifactPath)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name: "remote sourceURI uses remote source if local drop path verification fails",
			run: func(t *testing.T, fx *fixture) {
				dropPath := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()), []byte("bad artifact"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, fx.target.FileName()+".sha512"), hashFile, 0o644))
				fx.settings.DropPath = dropPath

				remotePath := "/beats/elastic-agent/" + fx.target.FileName()
				serverURL, requestCounts := newFileServer(t, map[string][]byte{
					remotePath:             archiveContent,
					remotePath + ".sha512": hashFile,
					remotePath + ".asc":    signature,
				})

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, serverURL,
					fx.upgradeDetails, false, true, pgpSource)
				require.NoError(t, err)
				require.Equal(t, 1, requestCounts[remotePath])
				require.Equal(t, 1, requestCounts[remotePath+".sha512"])
				require.Equal(t, 1, requestCounts[remotePath+".asc"])
				got, err := os.ReadFile(artifactPath)
				require.NoError(t, err)
				require.Equal(t, archiveContent, got)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name:    "remote snapshot sourceURI with buildID uses the stripped file name for the drop path",
			version: agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "6d69ee76"),
			run: func(t *testing.T, fx *fixture) {
				strippedName := "elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz"
				strippedHashFile := []byte(fmt.Sprintf("%x %s", sha512.Sum512(archiveContent), strippedName))

				dropPath := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, strippedName), archiveContent, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, strippedName+".sha512"), strippedHashFile, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, strippedName+".asc"), signature, 0o644))
				fx.settings.DropPath = dropPath

				serverURL, requestCounts := newFileServer(t, nil)

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, serverURL,
					fx.upgradeDetails, false, true, pgpSource)
				require.NoError(t, err)
				require.Empty(t, requestCounts)
				require.Equal(t, filepath.Join(paths.Downloads(), strippedName), artifactPath)
				require.FileExists(t, artifactPath)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name:    "remote snapshot sourceURI with buildID downloads the stripped file name",
			version: agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "6d69ee76"),
			run: func(t *testing.T, fx *fixture) {
				strippedName := "elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz"
				strippedHashFile := []byte(fmt.Sprintf("%x %s", sha512.Sum512(archiveContent), strippedName))

				remotePath := "/beats/elastic-agent/" + strippedName
				serverURL, requestCounts := newFileServer(t, map[string][]byte{
					remotePath:             archiveContent,
					remotePath + ".sha512": strippedHashFile,
					remotePath + ".asc":    signature,
				})

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, serverURL,
					fx.upgradeDetails, false, true, pgpSource)
				require.NoError(t, err)
				require.Equal(t, 1, requestCounts[remotePath])
				require.Equal(t, filepath.Join(paths.Downloads(), strippedName), artifactPath)
				require.FileExists(t, artifactPath)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name:    "local snapshot sourceURI with buildID uses the stripped file name",
			version: agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "6d69ee76"),
			run: func(t *testing.T, fx *fixture) {
				strippedName := "elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz"
				strippedHashFile := []byte(fmt.Sprintf("%x %s", sha512.Sum512(archiveContent), strippedName))

				dropPath := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, strippedName), archiveContent, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, strippedName+".sha512"), strippedHashFile, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, strippedName+".asc"), signature, 0o644))

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, "file://"+dropPath,
					fx.upgradeDetails, false, true, pgpSource)
				require.NoError(t, err)
				require.Equal(t, filepath.Join(paths.Downloads(), strippedName), artifactPath)
				require.FileExists(t, artifactPath)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
		{
			name:    "default snapshot sourceURI looks up latest build ID",
			version: agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", ""),
			run: func(t *testing.T, fx *fixture) {
				snapshotPath := "/8.14.0-6d69ee76/downloads/beats/elastic-agent/" + fx.target.FileName()
				snapshotHashFile := []byte(fmt.Sprintf("%x %s", sha512.Sum512(archiveContent), fx.target.FileName()))
				snapshotFiles := map[string][]byte{
					"/latest/8.14.0-SNAPSHOT.json": []byte(`{"build_id":"8.14.0-6d69ee76"}`),
					snapshotPath:                   archiveContent,
					snapshotPath + ".sha512":       snapshotHashFile,
					snapshotPath + ".asc":          signature,
				}

				requestCounts := map[string]int{}
				upstream := httptest.NewTLSServer(requestCountHandler(snapshotFiles, requestCounts))
				t.Cleanup(upstream.Close)

				fx.settings.Proxy.URL = newConnectProxy(t, upstream.Listener.Addr().String())
				fx.settings.TLS = &tlscommon.Config{
					VerificationMode: tlscommon.VerifyNone,
				}

				artifactPath, err := fx.downloader.downloadArtifact(t.Context(), fx.target, "",
					fx.upgradeDetails, false, true, pgpSource)
				require.NoError(t, err)
				require.Equal(t, 1, requestCounts["/latest/8.14.0-SNAPSHOT.json"])
				require.Equal(t, 1, requestCounts[snapshotPath])
				require.Equal(t, 1, requestCounts[snapshotPath+".sha512"])
				require.Equal(t, 1, requestCounts[snapshotPath+".asc"])
				require.FileExists(t, artifactPath)
				require.FileExists(t, download.AddHashExtension(artifactPath))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetVersion := agtversion.NewParsedSemVer(1, 2, 3, "", "")
			if tt.version != nil {
				targetVersion = tt.version
			}

			paths.SetDownloads(filepath.Join(t.TempDir(), "downloads"))

			target, err := artifact.New("elastic-agent", false, targetVersion, "linux", "amd64")
			require.NoError(t, err)

			settings := &artifact.Config{
				TargetDirectory:        paths.Downloads(),
				RetrySleepInitDuration: time.Millisecond,
				HTTPTransportSettings: httpcommon.HTTPTransportSettings{
					Timeout: time.Second,
				},
			}
			testLogger, _ := loggertest.New(t.Name())
			downloader := newArtifactDownloader(settings, testLogger)
			downloader.getPGPSources = func(_ *logger.Logger, _ string, _ *agtversion.ParsedSemVer, pgpSources []string) []string {
				return pgpSources
			}

			tt.run(t, &fixture{
				downloader:     downloader,
				target:         target,
				settings:       settings,
				upgradeDetails: details.NewDetails(targetVersion.String(), details.StateRequested, ""),
			})
		})
	}
}

// mockUpgradeDetails returns a *details.Details value that has an observer registered on it for inspecting
// certain properties of the object being set and unset.  It also returns:
// - a *time.Time value, which will be not nil if Metadata.RetryUntil is set on the mock value,
// - a *bool value, which will be true if Metadata.RetryUntil is set and then unset on the mock value,
// - a *string value, which will be non-empty if Metadata.RetryErrorMsg is set on the mock value.
func mockUpgradeDetails(parsedVersion *agtversion.ParsedSemVer) (*details.Details, *time.Time, *bool, *string) {
	var upgradeDetailsRetryUntil time.Time
	var upgradeDetailsRetryUntilWasUnset bool
	var upgradeDetailsRetryErrorMsg string

	upgradeDetails := details.NewDetails(parsedVersion.String(), details.StateRequested, "")
	upgradeDetails.RegisterObserver(func(details *details.Details) {
		if details.Metadata.RetryUntil != nil {
			upgradeDetailsRetryUntil = *details.Metadata.RetryUntil
		}

		if !upgradeDetailsRetryUntil.IsZero() && details.Metadata.RetryUntil == nil {
			upgradeDetailsRetryUntilWasUnset = true
		}

		if details.Metadata.RetryErrorMsg != "" {
			upgradeDetailsRetryErrorMsg = details.Metadata.RetryErrorMsg
		}
	})

	return upgradeDetails,
		&upgradeDetailsRetryUntil, &upgradeDetailsRetryUntilWasUnset,
		&upgradeDetailsRetryErrorMsg
}

func TestWithFleetServerURI(t *testing.T) {
	a := &artifactDownloader{}
	a.withFleetServerURI("mockURI")
	require.Equal(t, "mockURI", a.fleetServerURI)
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name      string
		sourceURI string
		version   *agtversion.ParsedSemVer
		want      string
	}{
		{
			name:      "schemeless sourceURI starting with / resolves as local",
			sourceURI: "/tmp",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "file:///tmp/elastic-agent-1.2.3-linux-x86_64.tar.gz",
		},
		{
			name:      "schemeless sourceURI not starting with / resolves as https",
			sourceURI: "mirror.example.com/downloads",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://mirror.example.com/downloads/beats/elastic-agent/elastic-agent-1.2.3-linux-x86_64.tar.gz",
		},
		{
			name:      "release version with default https sourceURI",
			sourceURI: artifact.DefaultSourceURI,
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-1.2.3-linux-x86_64.tar.gz",
		},
		{
			name:      "release version (+buildID) with default https sourceURI",
			sourceURI: artifact.DefaultSourceURI,
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", "build19700101"),
			want:      "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz",
		},
		{
			name:      "snapshot version with default https sourceURI",
			sourceURI: artifact.DefaultSourceURI,
			version:   agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "6d69ee76"),
			want:      "https://snapshots.elastic.co/8.14.0-6d69ee76/downloads/beats/elastic-agent/elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz",
		},
		{
			name:      "snapshot version (+buildID) with default https sourceURI",
			sourceURI: artifact.DefaultSourceURI,
			version:   agtversion.NewParsedSemVer(8, 13, 3, "SNAPSHOT", "76ce1a63"),
			want:      "https://snapshots.elastic.co/8.13.3-76ce1a63/downloads/beats/elastic-agent/elastic-agent-8.13.3-SNAPSHOT-linux-x86_64.tar.gz",
		},
		{
			name:      "release version with https non-default sourceURI",
			sourceURI: "https://mirror.example.com",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://mirror.example.com/beats/elastic-agent/elastic-agent-1.2.3-linux-x86_64.tar.gz",
		},
		{
			name:      "release version (+buildID) with https non-default sourceURI",
			sourceURI: "https://mirror.example.com",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", "build19700101"),
			want:      "https://mirror.example.com/beats/elastic-agent/elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz",
		},
		{
			name:      "snapshot version with https non-default sourceURI",
			sourceURI: "https://mirror.example.com/downloads",
			version:   agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", ""),
			want:      "https://mirror.example.com/downloads/beats/elastic-agent/elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz",
		},
		{
			name:      "snapshot version (+buildID) with https non-default sourceURI",
			sourceURI: "https://mirror.example.com/downloads",
			version:   agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "76ce1a63"),
			want:      "https://mirror.example.com/downloads/beats/elastic-agent/elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz",
		},
		{
			name:      "local snapshot file URI (+buildID) strips the buildID from the file name",
			sourceURI: "file:///tmp",
			version:   agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "76ce1a63"),
			want:      "file:///tmp/elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := artifact.New("elastic-agent", false, tt.version, "linux", "amd64")
			require.NoError(t, err)

			fileName := target.FileName()
			if tt.version.IsSnapshot() {
				fileName = strings.Replace(fileName, tt.version.String(), tt.version.VersionWithPrerelease(), 1)
			}

			upgradeDetails := details.NewDetails(tt.version.String(), details.StateRequested, "")
			source, err := Resolve(t.Context(), &artifact.Config{}, target, tt.sourceURI, "beats/elastic-agent", fileName, upgradeDetails)
			require.NoError(t, err)
			assert.Equal(t, tt.want, source)
		})
	}
}

func TestLatestSnapshotBuildID(t *testing.T) {
	version := agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "")

	snapshotInfo, err := os.ReadFile("./artifact/download/testdata/latest-snapshot.json")
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		config := newMockResolveConfig(t, func(rw http.ResponseWriter, _ *http.Request) {
			_, err := rw.Write(snapshotInfo)
			assert.NoError(t, err)
		})

		upgradeDetails, _, _, _ := mockUpgradeDetails(version)

		buildID, err := latestSnapshotBuildID(t.Context(), config, version, upgradeDetails)
		require.NoError(t, err)
		assert.Equal(t, "6d69ee76", buildID)
	})

	t.Run("success after one retry", func(t *testing.T) {
		requests := 0
		config := newMockResolveConfig(t, func(rw http.ResponseWriter, _ *http.Request) {
			requests++
			if requests == 1 {
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, err := rw.Write(snapshotInfo)
			assert.NoError(t, err)
		})
		config.RetrySleepInitDuration = 10 * time.Millisecond

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(version)

		buildID, err := latestSnapshotBuildID(t.Context(), config, version, upgradeDetails)
		require.NoError(t, err)
		assert.Equal(t, "6d69ee76", buildID)
		assert.Equal(t, 2, requests)

		// Retry details were set while retrying and cleared upon success.
		assert.NotZero(t, *upgradeDetailsRetryUntil)
		assert.True(t, *upgradeDetailsRetryUntilWasUnset)
		assert.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
		assert.Nil(t, upgradeDetails.Metadata.RetryUntil)
		assert.Empty(t, upgradeDetails.Metadata.RetryErrorMsg)
	})

	t.Run("failure not found", func(t *testing.T) {
		requests := 0
		config := newMockResolveConfig(t, func(rw http.ResponseWriter, _ *http.Request) {
			requests++
			rw.WriteHeader(http.StatusNotFound)
		})

		upgradeDetails, _, _, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(version)

		_, err := latestSnapshotBuildID(t.Context(), config, version, upgradeDetails)
		require.ErrorContains(t, err, "not found")

		// A 404 is a permanent error: no retries and no retryable error reported.
		assert.Equal(t, 1, requests)
		assert.Empty(t, *upgradeDetailsRetryErrorMsg)
	})

	t.Run("failure timeout", func(t *testing.T) {
		config := newMockResolveConfig(t, func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusInternalServerError)
		})
		config.Timeout = time.Second
		config.RetrySleepInitDuration = 10 * time.Millisecond

		upgradeDetails, _, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(version)

		started := time.Now()
		_, err := latestSnapshotBuildID(t.Context(), config, version, upgradeDetails)
		elapsed := time.Since(started)

		require.Error(t, err)
		assert.Less(t, elapsed, 10*time.Second)

		// Retry details remain set after exhausting the retry deadline.
		require.NotNil(t, upgradeDetails.Metadata.RetryUntil)
		assert.WithinDuration(t, started.Add(config.Timeout), *upgradeDetails.Metadata.RetryUntil, 500*time.Millisecond)
		assert.False(t, *upgradeDetailsRetryUntilWasUnset)
		assert.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
	})
}

func newConnectProxy(t *testing.T, upstreamAddr string) *httpcommon.ProxyURI {
	t.Helper()

	proxyServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !assert.Equal(t, http.MethodConnect, req.Method) {
			return
		}
		upstreamConn, err := (&net.Dialer{}).DialContext(req.Context(), "tcp", upstreamAddr)
		if !assert.NoError(t, err) {
			return
		}
		hijacker, ok := rw.(http.Hijacker)
		if !assert.True(t, ok) {
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if !assert.NoError(t, err) {
			return
		}
		_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if !assert.NoError(t, err) {
			return
		}
		go func() {
			defer upstreamConn.Close()
			defer clientConn.Close()
			_, _ = io.Copy(upstreamConn, clientConn)
		}()
		go func() {
			defer upstreamConn.Close()
			defer clientConn.Close()
			_, _ = io.Copy(clientConn, upstreamConn)
		}()
	}))
	t.Cleanup(proxyServer.Close)

	proxyURL, err := httpcommon.NewProxyURIFromString(proxyServer.URL)
	require.NoError(t, err)

	return proxyURL
}

func newMockResolveConfig(t *testing.T, snapshotHandler http.HandlerFunc) *artifact.Config {
	t.Helper()

	snapshotServer := httptest.NewTLSServer(snapshotHandler)
	t.Cleanup(snapshotServer.Close)

	return &artifact.Config{
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: 10 * time.Second,
			Proxy: httpcommon.HTTPClientProxySettings{
				URL: newConnectProxy(t, snapshotServer.Listener.Addr().String()),
			},
			TLS: &tlscommon.Config{
				VerificationMode: tlscommon.VerifyNone,
			},
		},
	}
}
