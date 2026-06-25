// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package download

import (
	"bytes"
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/proxytest"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/internal/pkg/testutils/fipsutils"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/pgptest"
)

func TestAppendFallbackPGP(t *testing.T) {
	testAgentVersion123 := agtversion.NewParsedSemVer(1, 2, 3, "", "")
	testCases := []struct {
		name                 string
		passedBytes          []string
		expectedLen          int
		expectedDefaultIdx   int
		expectedSecondaryIdx int
		fleetServerURI       string
		targetVersion        *agtversion.ParsedSemVer
	}{
		{"nil input", nil, 1, 0, -1, "", testAgentVersion123},
		{"empty input", []string{}, 1, 0, -1, "", testAgentVersion123},
		{"valid input with pgp", []string{"pgp-bytes"}, 2, 1, -1, "", nil},
		{"valid input with pgp and version, no fleet uri", []string{"pgp-bytes"}, 2, 1, -1, "", testAgentVersion123},
		{"valid input with pgp and version and fleet uri", []string{"pgp-bytes"}, 3, 1, 2, "some-uri", testAgentVersion123},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			log, _ := loggertest.New(tc.name)
			res := AppendFallbackPGP(log, tc.fleetServerURI, tc.targetVersion, tc.passedBytes)
			// check default fallback is passed and is very last
			require.NotNil(t, res)
			require.Equal(t, tc.expectedLen, len(res))
			require.Equal(t, PgpSourceURIPrefix+defaultUpgradeFallbackPGP, res[tc.expectedDefaultIdx])

			if tc.expectedSecondaryIdx >= 0 {
				// last element is fleet uri
				expectedPgpURI := PgpSourceURIPrefix + tc.fleetServerURI + fmt.Sprintf(fleetUpgradeFallbackPGPFormat, tc.targetVersion.Major(), tc.targetVersion.Minor(), tc.targetVersion.Patch())
				require.Equal(t, expectedPgpURI, res[len(res)-1])
			}
		})
	}
}

func TestPgpBytesFromSource(t *testing.T) {
	testCases := []struct {
		Name         string
		Source       string
		ClientDoErr  error
		ClientBody   []byte
		ClientStatus int

		ExpectedPGP        []byte
		ExpectedErr        error
		ExpectedLogMessage string
	}{
		{
			"successful call",
			PgpSourceURIPrefix + "https://location/path",
			nil,
			[]byte("pgp-body"),
			200,
			[]byte("pgp-body"),
			nil,
			"",
		},
		{
			"unknown source call",
			"https://location/path",
			nil,
			[]byte("pgp-body"),
			200,
			nil,
			ErrUnknownPGPSource,
			"",
		},
		{
			"invalid location is filtered call",
			PgpSourceURIPrefix + "http://location/path",
			nil,
			[]byte("pgp-body"),
			200,
			nil,
			nil,
			"Skipped remote PGP located ",
		},
		{
			"do error is filtered",
			PgpSourceURIPrefix + "https://location/path",
			errors.New("error"),
			[]byte("pgp-body"),
			200,
			nil,
			nil,
			"Skipped remote PGP located",
		},
		{
			"invalid status code is filtered out",
			PgpSourceURIPrefix + "https://location/path",
			nil,
			[]byte("pgp-body"),
			500,
			nil,
			nil,
			"Failed to fetch remote PGP",
		},
		{
			"invalid status code is filtered out",
			PgpSourceURIPrefix + "https://location/path",
			nil,
			[]byte("pgp-body"),
			404,
			nil,
			nil,
			"Failed to fetch remote PGP",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			log, obs := loggertest.New(tc.Name)
			mockClient := &MockClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					if tc.ClientDoErr != nil {
						return nil, tc.ClientDoErr
					}

					return &http.Response{
						StatusCode: tc.ClientStatus,
						Body:       io.NopCloser(bytes.NewReader(tc.ClientBody)),
					}, nil
				},
			}

			resPgp, resErr := PgpBytesFromSource(log, tc.Source, mockClient)
			require.Equal(t, tc.ExpectedErr, resErr)
			require.Equal(t, tc.ExpectedPGP, resPgp)
			if tc.ExpectedLogMessage != "" {
				logs := obs.FilterMessageSnippet(tc.ExpectedLogMessage)
				require.NotEqual(t, 0, logs.Len())
			}

		})
	}
}

func TestVerifySHA512Hash_BrokenHashFile(t *testing.T) {

	const data = "" +
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. " +
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. " +
		"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. " +
		"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
	// if you change data, the constant below should be updated
	const correct_data_hash = "8ba760cac29cb2b2ce66858ead169174057aa1298ccd581514e6db6dee3285280ee6e3a54c9319071dc8165ff061d77783100d449c937ff1fb4cd1bb516a69b9"

	const filename = "lorem_ipsum.txt"
	const hashFileName = filename + ".sha512"

	type skipFunc func(t *testing.T)

	type testcase struct {
		name            string
		skip            skipFunc
		hash            []byte
		hashPermissions fs.FileMode
		wantErr         assert.ErrorAssertionFunc
	}

	testcases := []testcase{
		{
			name:            "happy path - correct hash and format",
			hash:            []byte(correct_data_hash + "  " + filename),
			hashPermissions: 0o640,
			wantErr:         assert.NoError,
		},
		{
			name:            "happy path - broken lines before correct hash and format",
			hash:            []byte("this_is just_filler\n" + "some_more_filler\n" + correct_data_hash + "  " + filename),
			hashPermissions: 0o640,
			wantErr:         assert.NoError,
		},
		{
			name:            "truncated hash line - no filename",
			hash:            []byte(correct_data_hash),
			hashPermissions: 0o640,
			wantErr:         assert.Error,
		},
		{
			name:            "truncated hash",
			hash:            []byte(correct_data_hash[:8] + "  " + filename),
			hashPermissions: 0o640,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				target := new(ChecksumMismatchError)
				return assert.ErrorAs(t, err, &target, "mismatched hash has a specific error type", i)
			},
		},
		{
			name:            "empty hash file",
			hash:            []byte{},
			hashPermissions: 0o640,
			wantErr:         assert.Error,
		},
		{
			name: "non-existing hash file",
			hash: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, fs.ErrNotExist, i)
			},
		},
		{
			name: "unreadable hash file",
			skip: func(t *testing.T) {
				if runtime.GOOS == "windows" {
					t.Skip("write-only permissions cannot be set on windows")
				}
			},
			hash:            []byte(correct_data_hash + "  " + filename),
			hashPermissions: 0o222,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, fs.ErrPermission, i)
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip != nil {
				tt.skip(t)
			}

			dir := t.TempDir()
			dataFilePath := filepath.Join(dir, filename)
			err := os.WriteFile(dataFilePath, []byte(data), 0o750)
			require.NoError(t, err, "could not write sample data file")

			if tt.hash != nil {
				hashFilePath := filepath.Join(dir, hashFileName)
				err = os.WriteFile(hashFilePath, tt.hash, tt.hashPermissions)
				require.NoError(t, err, "could not write test hash file")
			}

			err = VerifySHA512Hash(dataFilePath)
			tt.wantErr(t, err)
		})
	}
}

type MockClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

var verifierTestArtifact = artifact.Artifact{
	Name:    "elastic-agent",
	OS:      "linux",
	Arch:    "386",
	Version: agtversion.NewParsedSemVer(7, 5, 1, "", ""),
}

func TestVerify(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "verifier being tested uses an OpenPGP key which results in a SHA-1 violation.")

	content := []byte("sample content")
	fileName := verifierTestArtifact.FileName()
	validHash := []byte(fmt.Sprintf("%x %s", sha512.Sum512(content), fileName))
	pgpKey, signature := pgptest.Sign(t, bytes.NewReader(content))

	type fixture struct {
		log    *logger.Logger
		config *artifact.Config
		setup  func(*testing.T, map[string][]byte) (string, string)
	}

	tests := []struct {
		name string
		run  func(*testing.T, *fixture)
	}{
		{
			name: "succeed when verification passes",
			run: func(t *testing.T, fx *fixture) {
				srcURI, artifactPath := fx.setup(t, map[string][]byte{
					fileName:             content,
					fileName + ".sha512": validHash,
					fileName + ".asc":    signature,
				})

				err := Verify(t.Context(), fx.log, fx.config, pgpKey, srcURI, artifactPath, false)
				require.NoError(t, err)
				assert.FileExists(t, artifactPath)
				assert.FileExists(t, artifactPath+".sha512")
			},
		},
		{
			name: "fail when checksum mismatches",
			run: func(t *testing.T, fx *fixture) {
				srcURI, artifactPath := fx.setup(t, map[string][]byte{
					fileName:             content,
					fileName + ".sha512": []byte(strings.Repeat("0", 128) + " " + fileName),
				})

				err := Verify(t.Context(), fx.log, fx.config, pgpKey, srcURI, artifactPath, false)
				var checksumErr *ChecksumMismatchError
				require.ErrorAs(t, err, &checksumErr)
			},
		},
		{
			name: "fail when signature is invalid",
			run: func(t *testing.T, fx *fixture) {
				srcURI, artifactPath := fx.setup(t, map[string][]byte{
					fileName:             content,
					fileName + ".sha512": validHash,
					fileName + ".asc":    []byte("not a valid signature"),
				})

				err := Verify(t.Context(), fx.log, fx.config, pgpKey, srcURI, artifactPath, false)
				var invalidSigErr *InvalidSignatureError
				require.ErrorAs(t, err, &invalidSigErr)
			},
		},
		{
			name: "fail when .asc is missing",
			run: func(t *testing.T, fx *fixture) {
				srcURI, artifactPath := fx.setup(t, map[string][]byte{
					fileName:             content,
					fileName + ".sha512": validHash,
				})

				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				err := Verify(ctx, fx.log, fx.config, pgpKey, srcURI, artifactPath, false)
				require.ErrorContains(t, err, "could not get .asc file")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, source := range []string{"local", "remote"} {
				t.Run(source, func(t *testing.T) {
					log, _ := loggertest.New(t.Name())
					config := &artifact.Config{
						TargetDirectory: t.TempDir(),
						HTTPTransportSettings: httpcommon.HTTPTransportSettings{
							Timeout: 30 * time.Second,
						},
					}

					tt.run(t, &fixture{
						log:    log,
						config: config,
						setup: func(t *testing.T, files map[string][]byte) (string, string) {
							t.Helper()
							artifactPath := filepath.Join(config.TargetDirectory, fileName)

							if source == "remote" {
								server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
									body, ok := files[strings.TrimPrefix(r.URL.Path, "/beats/elastic-agent/")]
									if !ok {
										w.WriteHeader(http.StatusNotFound)
										return
									}
									_, _ = w.Write(body)
								}))
								t.Cleanup(server.Close)

								srcURI := server.URL + "/beats/elastic-agent/" + fileName
								upgradeDetails := details.NewDetails(verifierTestArtifact.Version.String(), details.StateRequested, "")
								require.NoError(t, download(t.Context(), log, config, upgradeDetails, nil, srcURI, artifactPath, defaultFileOps()))
								require.NoError(t, download(t.Context(), log, config, upgradeDetails, nil, srcURI+".sha512", artifactPath+".sha512", defaultFileOps()))
								return srcURI, artifactPath
							}

							srcDir := t.TempDir()
							for name, body := range files {
								require.NoError(t, os.WriteFile(filepath.Join(srcDir, name), body, 0o644))
							}
							srcPath := filepath.Join(srcDir, fileName)
							require.NoError(t, copy(log, srcPath, artifactPath, defaultFileOps()))
							require.NoError(t, copy(log, srcPath+".sha512", artifactPath+".sha512", defaultFileOps()))
							return "file://" + srcPath, artifactPath
						},
					})
				})
			}
		})
	}
}

func TestVerifySkipsUnreachableRemotePGP(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "verifier being tested uses an OpenPGP key which results in a SHA-1 violation.")

	content := []byte("sample content")
	fileName := verifierTestArtifact.FileName()
	pgpKey, signature := pgptest.Sign(t, bytes.NewReader(content))

	srcPath := filepath.Join(t.TempDir(), fileName)
	require.NoError(t, os.WriteFile(srcPath+".asc", signature, 0o644))

	artifactPath := filepath.Join(t.TempDir(), fileName)
	require.NoError(t, os.WriteFile(artifactPath, content, 0o644))
	require.NoError(t, os.WriteFile(artifactPath+".sha512", []byte(fmt.Sprintf("%x %s", sha512.Sum512(content), fileName)), 0o644))

	log, obs := loggertest.New(t.Name())
	err := Verify(t.Context(), log, &artifact.Config{}, pgpKey, "file://"+srcPath, artifactPath, false,
		PgpSourceURIPrefix+"http://127.0.0.1:2874/path/does/not/exist")
	require.NoError(t, err)
	require.Equal(t, 1, obs.FilterMessageSnippet("Skipped remote PGP located at").Len())
}

func TestVerifyFailsWhenDefaultPGPKeyDoesNotMatch(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "verifier being tested uses an OpenPGP key which results in a SHA-1 violation.")

	content := []byte("sample content")
	fileName := verifierTestArtifact.FileName()
	_, signature := pgptest.Sign(t, bytes.NewReader(content))

	srcPath := filepath.Join(t.TempDir(), fileName)
	require.NoError(t, os.WriteFile(srcPath+".asc", signature, 0o644))

	artifactPath := filepath.Join(t.TempDir(), fileName)
	require.NoError(t, os.WriteFile(artifactPath, content, 0o644))
	require.NoError(t, os.WriteFile(artifactPath+".sha512", []byte(fmt.Sprintf("%x %s", sha512.Sum512(content), fileName)), 0o644))

	log, _ := loggertest.New(t.Name())
	err := Verify(t.Context(), log, &artifact.Config{}, release.PGP(), "file://"+srcPath, artifactPath, false)
	require.Error(t, err)
	assert.NoFileExists(t, artifactPath+".asc")
}

func TestVerifyRemoteRetriesSignatureFetch(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "verifier being tested uses an OpenPGP key which results in a SHA-1 violation.")

	content := []byte("sample content")
	pub, sig := pgptest.Sign(t, bytes.NewReader(content))
	fileName := verifierTestArtifact.FileName()
	files := map[string][]byte{
		"/beats/elastic-agent/" + fileName:             content,
		"/beats/elastic-agent/" + fileName + ".sha512": []byte(fmt.Sprintf("%x %s", sha512.Sum512(content), fileName)),
	}

	var ascRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/beats/elastic-agent/"+fileName+".asc" {
			ascRequests++
			if ascRequests <= 2 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(sig)
			return
		}

		body, ok := files[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	log, _ := loggertest.New("TestVerifyRemoteRetriesSignatureFetch")
	config := &artifact.Config{
		TargetDirectory: t.TempDir(),
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: 30 * time.Second,
		},
	}
	srcURI := server.URL + "/beats/elastic-agent/" + fileName
	artifactPath := filepath.Join(config.TargetDirectory, fileName)
	upgradeDetails := details.NewDetails(verifierTestArtifact.Version.String(), details.StateRequested, "")
	require.NoError(t, download(t.Context(), log, config, upgradeDetails, nil, srcURI, artifactPath, defaultFileOps()))
	require.NoError(t, download(t.Context(), log, config, upgradeDetails, nil, srcURI+".sha512", artifactPath+".sha512", defaultFileOps()))

	err := Verify(t.Context(), log, config, pub, srcURI, artifactPath, false)
	require.NoError(t, err)
	require.Equal(t, 3, ascRequests)
}

func TestVerifyRemoteWithProxy(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "verifier being tested uses an OpenPGP key which results in a SHA-1 violation.")

	content := []byte("sample content")
	pub, sig := pgptest.Sign(t, bytes.NewReader(content))
	fileName := verifierTestArtifact.FileName()
	files := map[string][]byte{
		"/beats/elastic-agent/" + fileName:             content,
		"/beats/elastic-agent/" + fileName + ".sha512": []byte(fmt.Sprintf("%x %s", sha512.Sum512(content), fileName)),
		"/beats/elastic-agent/" + fileName + ".asc":    sig,
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	var directRequests int
	brokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directRequests++
		w.WriteHeader(http.StatusTeapot)
		t.Log("[brokenServer] wrong server, is the proxy working?")
		_, _ = w.Write([]byte(`wrong server, is the proxy working?`))
	}))
	defer brokenServer.Close()

	proxy := proxytest.New(t,
		proxytest.WithRewriteFn(func(u *url.URL) {
			u.Host = originURL.Host
		}),
		proxytest.WithRequestLog("proxy", func(_ string, _ ...any) {}),
	)
	err = proxy.Start()
	require.NoError(t, err)
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.LocalhostURL)
	require.NoError(t, err)

	log, _ := loggertest.New("TestVerifyRemoteWithProxy")
	config := &artifact.Config{
		TargetDirectory: t.TempDir(),
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: time.Second,
			Proxy: httpcommon.HTTPClientProxySettings{
				URL: (*httpcommon.ProxyURI)(proxyURL),
			},
		},
	}
	srcURI := brokenServer.URL + "/beats/elastic-agent/" + fileName
	artifactPath := filepath.Join(config.TargetDirectory, fileName)
	upgradeDetails := details.NewDetails(verifierTestArtifact.Version.String(), details.StateRequested, "")
	require.NoError(t, download(t.Context(), log, config, upgradeDetails, nil, srcURI, artifactPath, defaultFileOps()))
	require.NoError(t, download(t.Context(), log, config, upgradeDetails, nil, srcURI+".sha512", artifactPath+".sha512", defaultFileOps()))

	err = Verify(t.Context(), log, config, pub, srcURI, artifactPath, false)
	require.NoError(t, err)
	require.Equal(t, 0, directRequests)
}
