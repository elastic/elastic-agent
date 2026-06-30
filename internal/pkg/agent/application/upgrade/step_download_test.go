// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"bytes"
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/download"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/pgptest"
)

func TestDownloadArtifact(t *testing.T) {
	originalTop := paths.Top()
	originalDownloads := paths.Downloads()
	t.Cleanup(func() {
		paths.SetTop(originalTop)
		paths.SetDownloads(originalDownloads)
	})

	parsedVersion := agtversion.NewParsedSemVer(8, 9, 0, "", "")
	newSettings := func() download.Config {
		return download.Config{
			TargetDirectory:        paths.Downloads(),
			RetrySleepInitDuration: time.Millisecond,
			HTTPTransportSettings: httpcommon.HTTPTransportSettings{
				Timeout: time.Second,
			},
		}
	}
	writeArtifact := func(t *testing.T, dir string, filename string, content []byte) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, filename), content, 0o644))
	}
	writeArtifactHash := func(t *testing.T, dir string, filename string, content []byte) {
		t.Helper()

		hash := sha512.Sum512(content)
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, filename+".sha512"),
			[]byte(fmt.Sprintf("%x %s", hash, filename)),
			0o644,
		))
	}
	setupPGP := func(t *testing.T, content []byte) ([]string, []byte) {
		t.Helper()

		pgpKey, signature := pgptest.Sign(t, bytes.NewReader(content))
		return []string{download.PgpSourceRawPrefix + string(pgpKey)}, signature
	}
	setupHTTPServer := func(t *testing.T, files map[string][]byte, missingStatus int) (string, map[string]int) {
		t.Helper()

		requestCounts := map[string]int{}
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			requestCounts[path]++

			file, ok := files[path]
			if !ok {
				w.WriteHeader(missingStatus)
				return
			}

			w.WriteHeader(http.StatusOK)
			_, writeErr := w.Write(file)
			require.NoError(t, writeErr, "error writing response content")
		}))
		t.Cleanup(testServer.Close)

		return testServer.URL, requestCounts
	}
	setupHTTPSProxy := func(t *testing.T, files map[string][]byte, missingStatus int) (*httpcommon.ProxyURI, map[string]int) {
		t.Helper()

		requestCounts := map[string]int{}
		upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			requestCounts[path]++

			file, ok := files[path]
			if !ok {
				w.WriteHeader(missingStatus)
				return
			}

			w.WriteHeader(http.StatusOK)
			_, writeErr := w.Write(file)
			require.NoError(t, writeErr, "error writing response content")
		}))
		t.Cleanup(upstream.Close)

		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodConnect, r.Method)

			var dialer net.Dialer
			upstreamConn, err := dialer.DialContext(r.Context(), "tcp", upstream.Listener.Addr().String())
			require.NoError(t, err)

			hijacker, ok := w.(http.Hijacker)
			require.True(t, ok)
			clientConn, _, err := hijacker.Hijack()
			require.NoError(t, err)

			_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			if err != nil {
				require.NoError(t, clientConn.Close())
				require.NoError(t, upstreamConn.Close())
				return
			}

			go func() {
				_, _ = io.Copy(upstreamConn, clientConn)
				_ = upstreamConn.Close()
				_ = clientConn.Close()
			}()
			go func() {
				_, _ = io.Copy(clientConn, upstreamConn)
				_ = upstreamConn.Close()
				_ = clientConn.Close()
			}()
		}))
		t.Cleanup(proxy.Close)

		proxyURI, err := httpcommon.NewProxyURIFromString(proxy.URL)
		require.NoError(t, err)

		return proxyURI, requestCounts
	}

	type downloadArtifactTestCase struct {
		name          string
		skipVerify    bool
		version       *agtversion.ParsedSemVer
		expectedFiles []string
		setup         func(*testing.T, download.Artifact) (download.Config, string, []string, func(*testing.T, string, error))
	}

	tests := []downloadArtifactTestCase{
		{
			name:          "local sourceURI copies from local source",
			expectedFiles: []string{"artifact", "hash"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				dropPath := t.TempDir()
				content := []byte("signed local artifact")
				pgpSources, signature := setupPGP(t, content)
				writeArtifact(t, dropPath, target.FileName, content)
				writeArtifactHash(t, dropPath, target.FileName, content)
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, target.FileName+".asc"), signature, 0o644))

				settings := newSettings()

				return settings, "file://" + dropPath, pgpSources, func(t *testing.T, artifactPath string, err error) {
					require.NoError(t, err)
					require.Equal(t, filepath.Join(paths.Downloads(), target.FileName), artifactPath)
				}
			},
		},
		{
			name:          "skip verification for local sourceURI if skipVerify is set",
			skipVerify:    true,
			expectedFiles: []string{"artifact"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				dropPath := t.TempDir()
				writeArtifact(t, dropPath, target.FileName, []byte("local artifact"))

				return newSettings(), "file://" + dropPath, nil, func(t *testing.T, artifactPath string, err error) {
					require.NoError(t, err)
					require.Equal(t, filepath.Join(paths.Downloads(), target.FileName), artifactPath)
				}
			},
		},
		{
			name:          "local sourceURI fails when local verification fails",
			expectedFiles: []string{"artifact", "hash"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				dropPath := t.TempDir()
				content := []byte("local artifact")
				pgpSources, _ := setupPGP(t, content)
				writeArtifact(t, dropPath, target.FileName, content)
				writeArtifactHash(t, dropPath, target.FileName, content)
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, target.FileName+".asc"), []byte("not a valid signature"), 0o644))

				settings := newSettings()

				return settings, "file://" + dropPath, pgpSources, func(t *testing.T, artifactPath string, err error) {
					require.Error(t, err)
					require.ErrorContains(t, err, "verification failed")
					require.Equal(t, filepath.Join(paths.Downloads(), target.FileName), artifactPath)
				}
			},
		},
		{
			name: "local sourceURI fails when local artifact is missing",
			setup: func(t *testing.T, _ download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				serverURL, requestCounts := setupHTTPServer(t, nil, http.StatusOK)

				settings := newSettings()
				settings.SourceURI = serverURL

				return settings, "file://" + t.TempDir(), nil, func(t *testing.T, _ string, err error) {
					require.Error(t, err)
					require.ErrorContains(t, err, "could not fetch artifact")
					require.Empty(t, requestCounts)
				}
			},
		},
		{
			name:          "local sourceURI fails when local artifact is missing its hash",
			expectedFiles: []string{"artifact"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				dropPath := t.TempDir()
				writeArtifact(t, dropPath, target.FileName, []byte("local artifact"))

				return newSettings(), "file://" + dropPath, nil, func(t *testing.T, _ string, err error) {
					require.Error(t, err)
					require.ErrorContains(t, err, "could not fetch artifact sha512")
				}
			},
		},
		{
			name:          "remote sourceURI copies from local drop path if available",
			expectedFiles: []string{"artifact", "hash"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				dropPath := t.TempDir()
				content := []byte("signed local artifact")
				pgpSources, signature := setupPGP(t, content)
				writeArtifact(t, dropPath, target.FileName, content)
				writeArtifactHash(t, dropPath, target.FileName, content)
				require.NoError(t, os.WriteFile(filepath.Join(dropPath, target.FileName+".asc"), signature, 0o644))

				serverURL, requestCounts := setupHTTPServer(t, nil, http.StatusInternalServerError)

				settings := newSettings()
				settings.DropPath = dropPath
				settings.SourceURI = serverURL

				return settings, serverURL, pgpSources, func(t *testing.T, artifactPath string, err error) {
					require.NoError(t, err)
					require.Equal(t, filepath.Join(paths.Downloads(), target.FileName), artifactPath)
					require.Empty(t, requestCounts)
				}
			},
		},
		{
			name:          "remote sourceURI uses remote source when drop path is set but artifact is missing",
			expectedFiles: []string{"artifact", "hash"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				dropPath := t.TempDir()

				remoteContent := []byte("signed remote artifact")
				pgpSources, signature := setupPGP(t, remoteContent)
				remoteHash := sha512.Sum512(remoteContent)
				remoteFiles := map[string][]byte{
					"/beats/elastic-agent/" + target.FileName:             remoteContent,
					"/beats/elastic-agent/" + target.FileName + ".sha512": []byte(fmt.Sprintf("%x %s", remoteHash, target.FileName)),
					"/beats/elastic-agent/" + target.FileName + ".asc":    signature,
				}

				serverURL, requestCounts := setupHTTPServer(t, remoteFiles, http.StatusNotFound)

				settings := newSettings()
				settings.DropPath = dropPath
				settings.SourceURI = serverURL

				return settings, serverURL, pgpSources, func(t *testing.T, artifactPath string, err error) {
					require.NoError(t, err)
					require.Equal(t, filepath.Join(paths.Downloads(), target.FileName), artifactPath)
					require.NotEmpty(t, requestCounts)
				}
			},
		},
		{
			name:          "remote sourceURI uses remote source if local drop path verification fails",
			expectedFiles: []string{"artifact", "hash"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				dropPath := t.TempDir()
				writeArtifact(t, dropPath, target.FileName, []byte("local artifact"))
				require.NoError(t, os.WriteFile(
					filepath.Join(dropPath, target.FileName+".sha512"),
					[]byte(strings.Repeat("0", 128)+" "+target.FileName),
					0o644,
				))

				remoteContent := []byte("signed remote artifact")
				pgpSources, signature := setupPGP(t, remoteContent)
				remoteHash := sha512.Sum512(remoteContent)
				remoteFiles := map[string][]byte{
					"/beats/elastic-agent/" + target.FileName:             remoteContent,
					"/beats/elastic-agent/" + target.FileName + ".sha512": []byte(fmt.Sprintf("%x %s", remoteHash, target.FileName)),
					"/beats/elastic-agent/" + target.FileName + ".asc":    signature,
				}

				serverURL, requestCounts := setupHTTPServer(t, remoteFiles, http.StatusNotFound)

				settings := newSettings()
				settings.DropPath = dropPath
				settings.SourceURI = serverURL

				return settings, serverURL, pgpSources, func(t *testing.T, artifactPath string, err error) {
					require.NoError(t, err)
					require.Equal(t, filepath.Join(paths.Downloads(), target.FileName), artifactPath)
					require.NotEmpty(t, requestCounts)
					got, err := os.ReadFile(artifactPath)
					require.NoError(t, err)
					require.Equal(t, remoteContent, got)
				}
			},
		},
		{
			name:          "remote sourceURI uses remote source when drop path is unset",
			expectedFiles: []string{"artifact", "hash"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				remoteContent := []byte("signed remote artifact")
				pgpSources, signature := setupPGP(t, remoteContent)
				remoteHash := sha512.Sum512(remoteContent)
				remoteFiles := map[string][]byte{
					"/beats/elastic-agent/" + target.FileName:             remoteContent,
					"/beats/elastic-agent/" + target.FileName + ".sha512": []byte(fmt.Sprintf("%x %s", remoteHash, target.FileName)),
					"/beats/elastic-agent/" + target.FileName + ".asc":    signature,
				}

				serverURL, requestCounts := setupHTTPServer(t, remoteFiles, http.StatusNotFound)

				settings := newSettings()
				settings.SourceURI = serverURL

				return settings, serverURL, pgpSources, func(t *testing.T, artifactPath string, err error) {
					require.NoError(t, err)
					require.Equal(t, filepath.Join(paths.Downloads(), target.FileName), artifactPath)
					require.NotEmpty(t, requestCounts)
				}
			},
		},
		{
			name:          "remote sourceURI fails when remote artifact is missing its hash",
			expectedFiles: []string{"artifact"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				files := map[string][]byte{
					"/beats/elastic-agent/" + target.FileName: []byte("This is a fake linux elastic agent archive"),
				}
				serverURL, requestCounts := setupHTTPServer(t, files, http.StatusNotFound)

				settings := newSettings()
				settings.SourceURI = serverURL

				return settings, serverURL, nil, func(t *testing.T, _ string, err error) {
					require.Error(t, err)
					require.ErrorContains(t, err, "could not fetch artifact sha512")
					require.Greater(t, requestCounts["/beats/elastic-agent/"+target.FileName+".sha512"], 0)
				}
			},
		},
		{
			name:          "skip verification for remote sourceURI if skipVerify is set",
			skipVerify:    true,
			expectedFiles: []string{"artifact"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				files := map[string][]byte{
					"/beats/elastic-agent/" + target.FileName: []byte("remote artifact"),
				}
				serverURL, requestCounts := setupHTTPServer(t, files, http.StatusNotFound)

				return newSettings(), serverURL, nil, func(t *testing.T, artifactPath string, err error) {
					require.NoError(t, err)
					require.Equal(t, filepath.Join(paths.Downloads(), target.FileName), artifactPath)
					require.Greater(t, requestCounts["/beats/elastic-agent/"+target.FileName], 0)
					require.Zero(t, requestCounts["/beats/elastic-agent/"+target.FileName+".sha512"])
				}
			},
		},
		{
			name:          "default snapshot sourceURI looks up latest build ID",
			version:       agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", ""),
			expectedFiles: []string{"artifact", "hash"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				remoteContent := []byte("signed snapshot artifact")
				pgpSources, signature := setupPGP(t, remoteContent)
				remoteHash := sha512.Sum512(remoteContent)
				remoteFiles := map[string][]byte{
					"/latest/8.14.0-SNAPSHOT.json":                                                  []byte(`{"build_id":"8.14.0-6d69ee76"}`),
					"/8.14.0-6d69ee76/downloads/beats/elastic-agent/" + target.FileName:             remoteContent,
					"/8.14.0-6d69ee76/downloads/beats/elastic-agent/" + target.FileName + ".sha512": []byte(fmt.Sprintf("%x %s", remoteHash, target.FileName)),
					"/8.14.0-6d69ee76/downloads/beats/elastic-agent/" + target.FileName + ".asc":    signature,
				}

				proxyURL, requestCounts := setupHTTPSProxy(t, remoteFiles, http.StatusNotFound)
				enabled := true
				settings := newSettings()
				settings.Proxy.URL = proxyURL
				settings.TLS = &tlscommon.Config{
					Enabled:          &enabled,
					VerificationMode: tlscommon.VerifyNone,
				}

				return settings, "", pgpSources, func(t *testing.T, artifactPath string, err error) {
					require.NoError(t, err)
					require.Equal(t, filepath.Join(paths.Downloads(), target.FileName), artifactPath)
					require.Greater(t, requestCounts["/latest/8.14.0-SNAPSHOT.json"], 0)
					require.Greater(t, requestCounts["/8.14.0-6d69ee76/downloads/beats/elastic-agent/"+target.FileName], 0)
				}
			},
		},
		{
			name:          "remote sourceURI fails when remote verification fails",
			expectedFiles: []string{"artifact", "hash"},
			setup: func(t *testing.T, target download.Artifact) (download.Config, string, []string, func(*testing.T, string, error)) {
				remoteContent := []byte("remote artifact")
				pgpSources, _ := setupPGP(t, remoteContent)
				remoteHash := sha512.Sum512(remoteContent)
				remoteFiles := map[string][]byte{
					"/beats/elastic-agent/" + target.FileName:             remoteContent,
					"/beats/elastic-agent/" + target.FileName + ".sha512": []byte(fmt.Sprintf("%x %s", remoteHash, target.FileName)),
					"/beats/elastic-agent/" + target.FileName + ".asc":    []byte("not a valid signature"),
				}

				serverURL, requestCounts := setupHTTPServer(t, remoteFiles, http.StatusNotFound)

				settings := newSettings()
				settings.SourceURI = serverURL

				return settings, serverURL, pgpSources, func(t *testing.T, artifactPath string, err error) {
					require.Error(t, err)
					require.ErrorContains(t, err, "verification failed")
					require.Equal(t, filepath.Join(paths.Downloads(), target.FileName), artifactPath)
					require.Greater(t, requestCounts["/beats/elastic-agent/"+target.FileName+".asc"], 0)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths.SetTop(t.TempDir())
			targetVersion := parsedVersion
			if tt.version != nil {
				targetVersion = tt.version
			}
			target, err := download.New("elastic-agent", false, targetVersion, "linux", "amd64")
			require.NoError(t, err)

			downloadsPath := filepath.Join(paths.Top(), "downloads")
			paths.SetDownloads(downloadsPath)
			settings, sourceURI, pgpSources, assertResult := tt.setup(t, target)
			testLogger, _ := loggertest.New(t.Name())
			artifactPath, err := newArtifactDownloader(&settings, testLogger).downloadArtifact(
				t.Context(),
				testLogger,
				target,
				sourceURI,
				details.NewDetails(parsedVersion.String(), details.StateRequested, ""),
				tt.skipVerify,
				true,
				pgpSources...,
			)
			assertResult(t, artifactPath, err)

			expectedArtifactPath := filepath.Join(paths.Downloads(), target.FileName)
			require.Equal(t, expectedArtifactPath, artifactPath)
			expectedHashPath := download.AddHashExtension(expectedArtifactPath)

			expectedFiles := map[string]string{
				"artifact": expectedArtifactPath,
				"hash":     expectedHashPath,
			}
			for expectedFile, expectedPath := range expectedFiles {
				if slices.Contains(tt.expectedFiles, expectedFile) {
					require.FileExists(t, expectedPath)
				} else {
					require.NoFileExists(t, expectedPath)
				}
			}
		})
	}
}

func TestWithFleetServerURI(t *testing.T) {
	a := &artifactDownloader{}
	a.withFleetServerURI("mockURI")
	require.Equal(t, "mockURI", a.fleetServerURI)
}

func TestResolve(t *testing.T) {
	dropPath := t.TempDir()

	tests := []struct {
		name      string
		sourceURI string
		os        string
		arch      string
		version   *agtversion.ParsedSemVer
		want      string
		wantLocal bool
	}{
		{
			name:      "empty source URI resolves as the default remote base",
			sourceURI: "",
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-1.2.3-linux-x86_64.tar.gz",
		},
		{
			name:      "release version",
			sourceURI: download.DefaultSourceURI,
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-1.2.3-linux-x86_64.tar.gz",
		},
		{
			name:      "release version on windows",
			sourceURI: download.DefaultSourceURI,
			os:        "windows",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-1.2.3-windows-x86_64.zip",
		},
		{
			name:      "release version on darwin",
			sourceURI: download.DefaultSourceURI,
			os:        "darwin",
			arch:      "arm64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-1.2.3-darwin-aarch64.tar.gz",
		},
		{
			name:      "release version with build metadata",
			sourceURI: download.DefaultSourceURI,
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", "build19700101"),
			want:      "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz",
		},
		{
			name:      "snapshot version with build metadata uses that buildID",
			sourceURI: download.DefaultSourceURI,
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(8, 13, 3, "SNAPSHOT", "76ce1a63"),
			want:      "https://snapshots.elastic.co/8.13.3-76ce1a63/downloads/beats/elastic-agent/elastic-agent-8.13.3-SNAPSHOT-linux-x86_64.tar.gz",
		},
		{
			name:      "custom source URI",
			sourceURI: "https://mirror.example.com/downloads",
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://mirror.example.com/downloads/beats/elastic-agent/elastic-agent-1.2.3-linux-x86_64.tar.gz",
		},
		{
			name:      "custom source URI snapshot build",
			sourceURI: "https://mirror.example.com/downloads",
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", ""),
			want:      "https://mirror.example.com/downloads/beats/elastic-agent/elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz",
		},
		{
			name:      "scheme-less source URI defaults to https",
			sourceURI: "mirror.example.com/downloads",
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://mirror.example.com/downloads/beats/elastic-agent/elastic-agent-1.2.3-linux-x86_64.tar.gz",
		},
		{
			name:      "file:// URI",
			sourceURI: "file://" + dropPath,
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "file://" + dropPath + "/elastic-agent-1.2.3-linux-x86_64.tar.gz",
			wantLocal: true,
		},
		{
			name:      "file:// URI with trailing slash",
			sourceURI: "file://" + dropPath + "/",
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "file://" + dropPath + "/elastic-agent-1.2.3-linux-x86_64.tar.gz",
			wantLocal: true,
		},
		{
			name:      "remote URI preserves query while joining artifact path",
			sourceURI: "https://mirror.example.com/downloads?token=abc",
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://mirror.example.com/downloads/beats/elastic-agent/elastic-agent-1.2.3-linux-x86_64.tar.gz?token=abc",
		},
		{
			name:      "remote URI path elements are cleaned while joining artifact path",
			sourceURI: "https://mirror.example.com/downloads/../artifacts",
			os:        "linux",
			arch:      "amd64",
			version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
			want:      "https://mirror.example.com/artifacts/beats/elastic-agent/elastic-agent-1.2.3-linux-x86_64.tar.gz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := download.New("elastic-agent", false, tt.version, tt.os, tt.arch)
			require.NoError(t, err)

			source, err := Resolve(a, tt.sourceURI)
			require.NoError(t, err)
			assert.Equal(t, tt.want, source)
			assert.Equal(t, tt.wantLocal, download.IsLocal(source))
		})
	}
}

func TestLatestSnapshotBuildID(t *testing.T) {
	t.Run("looks up latest build", func(t *testing.T) {
		snapshotJSON, err := os.ReadFile(filepath.Join("download", "testdata", "latest-snapshot.json"))
		require.NoError(t, err)
		files := map[string][]byte{
			"/latest/8.14.0-SNAPSHOT.json": snapshotJSON,
		}
		handleDownload := func(rw http.ResponseWriter, req *http.Request) {
			file, ok := files[req.URL.Path]
			if !ok {
				rw.WriteHeader(http.StatusNotFound)
				return
			}
			_, err := io.Copy(rw, bytes.NewReader(file))
			assert.NoError(t, err, "error writing out response body")
		}
		server := httptest.NewTLSServer(http.HandlerFunc(handleDownload))
		defer server.Close()

		client := server.Client()
		transport := client.Transport.(*http.Transport)
		transport.TLSClientConfig.InsecureSkipVerify = true
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, server.Listener.Addr().String())
		}

		a, err := download.New("elastic-agent", false, agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", ""), "linux", "amd64")
		require.NoError(t, err)

		buildID, err := latestSnapshotBuildID(context.TODO(), client, a.Version)
		require.NoError(t, err)
		assert.Equal(t, "6d69ee76", buildID)
	})
}
