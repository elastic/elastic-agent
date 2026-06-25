// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package download

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
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
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/internal/pkg/testutils/fipsutils"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
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

func TestVerifySHA512Hash_success(t *testing.T) {
	data := "I’m the Doctor. I’m a Time Lord. I’m from the planet " +
		"Gallifrey in the constellation of Kasterborous. I’m 903 years old and " +
		"I’m the man who’s going to save your lives and all 6 billion people on " +
		"the planet below. You got a problem with that?"
	dir := t.TempDir()
	filename := "file"
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	require.NoError(t, err, "could not create file")
	fsha512, err := os.Create(path + ".sha512")
	require.NoError(t, err, "could not create .sha512 file")

	_, err = fmt.Fprint(f, data)
	require.NoError(t, err, "could not write to file")
	hash := sha512.Sum512([]byte(data))
	_, err = fmt.Fprintf(fsha512, "%s %s", hex.EncodeToString(hash[:]), filename)
	require.NoError(t, err, "could not write to file")

	err = f.Close()
	require.NoError(t, err, "could not close file")
	err = fsha512.Close()
	require.NoError(t, err, "could not close .sha512 file")

	err = VerifySHA512Hash(path)
	assert.NoErrorf(t, err, "failed verifying sha512")
}

func TestVerifySHA512Hash_failure(t *testing.T) {
	data := "I’m the Doctor. I’m a Time Lord. I’m from the planet " +
		"Gallifrey in the constellation of Kasterborous. I’m 903 years old and " +
		"I’m the man who’s going to save your lives and all 6 billion people on " +
		"the planet below. You got a problem with that?"
	dir := t.TempDir()
	filename := "file"
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	require.NoError(t, err, "could not create file")
	fsha512, err := os.Create(path + ".sha512")
	require.NoError(t, err, "could not create .sha512 file")

	_, err = fmt.Fprint(f, data)
	require.NoError(t, err, "could not write to file")
	_, err = fmt.Fprintf(fsha512, "%s %s", "wrong-sha512", filename)
	require.NoError(t, err, "could not write to file")

	err = f.Close()
	require.NoError(t, err, "could not close file")
	err = fsha512.Close()
	require.NoError(t, err, "could not close .sha512 file")

	err = VerifySHA512Hash(path)
	assert.Errorf(t, err, "checksum verification should have failed")
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

var verifierTestArtifact = Artifact{
	Name:     "elastic-agent",
	Version:  agtversion.NewParsedSemVer(7, 5, 1, "", ""),
	FileName: "elastic-agent-7.5.1-linux-x86.tar.gz",
}

func prepareVerifierTestCase(t *testing.T, a Artifact, dir string) []byte {
	t.Helper()
	filePath := filepath.Join(dir, a.FileName)
	filePathSHA := filePath + ".sha512"
	filePathASC := filePath + ".asc"

	content := []byte("sample content")
	err := os.WriteFile(filePath, content, 0o644)
	require.NoErrorf(t, err, "could not write %q file", filePath)

	hash := sha512.Sum512(content)
	hashContent := fmt.Sprintf("%x %s", hash, a.FileName)
	err = os.WriteFile(filePathSHA, []byte(hashContent), 0o644)
	require.NoErrorf(t, err, "could not write %q file", filePathSHA)

	pub, sig := pgptest.Sign(t, bytes.NewReader(content))
	err = os.WriteFile(filePathASC, sig, 0o644)
	require.NoErrorf(t, err, "could not write %q file", filePathASC)

	return pub
}

func TestVerify(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "verifier being tested uses an OpenPGP key which results in a SHA-1 violation.")

	content := []byte("sample content")
	fileName := verifierTestArtifact.FileName
	validHash := func() []byte {
		hash := sha512.Sum512(content)
		return []byte(fmt.Sprintf("%x %s", hash, fileName))
	}

	signedFiles := func(t *testing.T) (map[string][]byte, []byte) {
		pgpKey, sig := pgptest.Sign(t, bytes.NewReader(content))
		return map[string][]byte{
			fileName:             content,
			fileName + ".sha512": validHash(),
			fileName + ".asc":    sig,
		}, pgpKey
	}
	prepareLocalSource := func(t *testing.T, log *logger.Logger, config *Config, files map[string][]byte) (string, string) {
		t.Helper()

		srcDir := t.TempDir()
		for name, body := range files {
			require.NoError(t, os.WriteFile(filepath.Join(srcDir, name), body, 0o644))
		}

		srcPath := filepath.Join(srcDir, fileName)
		artifactPath := filepath.Join(config.TargetDirectory, fileName)
		require.NoError(t, copy(log, srcPath, artifactPath, defaultFileOps()))
		require.NoError(t, copy(log, srcPath+".sha512", artifactPath+".sha512", defaultFileOps()))
		return "file://" + srcPath, artifactPath
	}
	prepareRemoteSource := func(t *testing.T, ctx context.Context, log *logger.Logger, config *Config, files map[string][]byte) (string, string) {
		t.Helper()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := strings.TrimPrefix(r.URL.Path, "/beats/elastic-agent/")
			body, ok := files[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(body)
			require.NoError(t, err)
		}))
		t.Cleanup(server.Close)

		srcURI := server.URL + "/beats/elastic-agent/" + fileName
		artifactPath := filepath.Join(config.TargetDirectory, fileName)
		require.NoError(t, download(ctx, log, config, nil, nil, srcURI, artifactPath, defaultFileOps()))
		require.NoError(t, download(ctx, log, config, nil, nil, srcURI+".sha512", artifactPath+".sha512", defaultFileOps()))
		return srcURI, artifactPath
	}

	type verifierTestCase struct {
		name  string
		setup func(
			t *testing.T,
			ctx context.Context,
			log *logger.Logger,
			config *Config,
		) (string, string, []byte, []string, func(*testing.T, error, int, string))
	}

	tests := []verifierTestCase{
		{
			name: "succeed when local verification passes",
			setup: func(t *testing.T, _ context.Context, log *logger.Logger, config *Config) (string, string, []byte, []string, func(*testing.T, error, int, string)) {
				files, pgpKey := signedFiles(t)
				srcURI, artifactPath := prepareLocalSource(t, log, config, files)
				return srcURI, artifactPath, pgpKey, nil, func(t *testing.T, err error, _ int, _ string) {
					require.NoError(t, err)
				}
			},
		},
		{
			name: "succeed when remote verification passes",
			setup: func(t *testing.T, ctx context.Context, log *logger.Logger, config *Config) (string, string, []byte, []string, func(*testing.T, error, int, string)) {
				files, pgpKey := signedFiles(t)
				srcURI, artifactPath := prepareRemoteSource(t, ctx, log, config, files)
				return srcURI, artifactPath, pgpKey, nil, func(t *testing.T, err error, _ int, _ string) {
					require.NoError(t, err)
				}
			},
		},
		{
			name: "succeed when local verification skips unreachable remote PGP",
			setup: func(t *testing.T, _ context.Context, log *logger.Logger, config *Config) (string, string, []byte, []string, func(*testing.T, error, int, string)) {
				files, pgpKey := signedFiles(t)
				srcURI, artifactPath := prepareLocalSource(t, log, config, files)
				pgpSources := []string{PgpSourceURIPrefix + "http://127.0.0.1:2874/path/does/not/exist"}
				return srcURI, artifactPath, pgpKey, pgpSources, func(t *testing.T, err error, skippedPGPLogs int, _ string) {
					require.NoError(t, err)
					require.Equal(t, 1, skippedPGPLogs)
				}
			},
		},
		{
			name: "fail when local default PGP key does not match",
			setup: func(t *testing.T, _ context.Context, log *logger.Logger, config *Config) (string, string, []byte, []string, func(*testing.T, error, int, string)) {
				files, _ := signedFiles(t)
				srcURI, artifactPath := prepareLocalSource(t, log, config, files)
				return srcURI, artifactPath, release.PGP(), nil, func(t *testing.T, err error, _ int, artifactPath string) {
					require.Error(t, err)
					assert.NoFileExists(t, artifactPath+".asc")
				}
			},
		},
		{
			name: "fail when local checksum mismatches",
			setup: func(t *testing.T, _ context.Context, log *logger.Logger, config *Config) (string, string, []byte, []string, func(*testing.T, error, int, string)) {
				files := map[string][]byte{
					fileName:             content,
					fileName + ".sha512": []byte(strings.Repeat("0", 128) + " " + fileName),
				}
				srcURI, artifactPath := prepareLocalSource(t, log, config, files)
				return srcURI, artifactPath, nil, nil, func(t *testing.T, err error, _ int, _ string) {
					var checksumErr *ChecksumMismatchError
					require.ErrorAs(t, err, &checksumErr)
				}
			},
		},
		{
			name: "fail when remote checksum mismatches",
			setup: func(t *testing.T, ctx context.Context, log *logger.Logger, config *Config) (string, string, []byte, []string, func(*testing.T, error, int, string)) {
				files := map[string][]byte{
					fileName:             content,
					fileName + ".sha512": []byte(strings.Repeat("0", 128) + " " + fileName),
				}
				srcURI, artifactPath := prepareRemoteSource(t, ctx, log, config, files)
				return srcURI, artifactPath, nil, nil, func(t *testing.T, err error, _ int, _ string) {
					var checksumErr *ChecksumMismatchError
					require.ErrorAs(t, err, &checksumErr)
				}
			},
		},
		{
			name: "fail when local signature is invalid",
			setup: func(t *testing.T, _ context.Context, log *logger.Logger, config *Config) (string, string, []byte, []string, func(*testing.T, error, int, string)) {
				pgpKey, _ := pgptest.Sign(t, bytes.NewReader(content))
				files := map[string][]byte{
					fileName:             content,
					fileName + ".sha512": validHash(),
					fileName + ".asc":    []byte("not a valid signature"),
				}
				srcURI, artifactPath := prepareLocalSource(t, log, config, files)
				return srcURI, artifactPath, pgpKey, nil, func(t *testing.T, err error, _ int, _ string) {
					var invalidSigErr *InvalidSignatureError
					require.ErrorAs(t, err, &invalidSigErr)
				}
			},
		},
		{
			name: "fail when remote signature is invalid",
			setup: func(t *testing.T, ctx context.Context, log *logger.Logger, config *Config) (string, string, []byte, []string, func(*testing.T, error, int, string)) {
				pgpKey, _ := pgptest.Sign(t, bytes.NewReader(content))
				files := map[string][]byte{
					fileName:             content,
					fileName + ".sha512": validHash(),
					fileName + ".asc":    []byte("not a valid signature"),
				}
				srcURI, artifactPath := prepareRemoteSource(t, ctx, log, config, files)
				return srcURI, artifactPath, pgpKey, nil, func(t *testing.T, err error, _ int, _ string) {
					var invalidSigErr *InvalidSignatureError
					require.ErrorAs(t, err, &invalidSigErr)
				}
			},
		},
		{
			name: "fail when local .asc is missing",
			setup: func(t *testing.T, _ context.Context, log *logger.Logger, config *Config) (string, string, []byte, []string, func(*testing.T, error, int, string)) {
				files := map[string][]byte{
					fileName:             content,
					fileName + ".sha512": validHash(),
				}
				srcURI, artifactPath := prepareLocalSource(t, log, config, files)
				return srcURI, artifactPath, nil, nil, func(t *testing.T, err error, _ int, _ string) {
					require.Error(t, err)
					assert.ErrorContains(t, err, "could not get .asc file")
				}
			},
		},
		{
			name: "fail when remote .asc is missing",
			setup: func(t *testing.T, ctx context.Context, log *logger.Logger, config *Config) (string, string, []byte, []string, func(*testing.T, error, int, string)) {
				files := map[string][]byte{
					fileName:             content,
					fileName + ".sha512": validHash(),
				}
				srcURI, artifactPath := prepareRemoteSource(t, ctx, log, config, files)
				return srcURI, artifactPath, nil, nil, func(t *testing.T, err error, _ int, _ string) {
					require.Error(t, err)
					assert.ErrorContains(t, err, "could not get .asc file")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			log, obs := loggertest.New(t.Name())
			config := &Config{
				TargetDirectory: t.TempDir(),
				HTTPTransportSettings: httpcommon.HTTPTransportSettings{
					Timeout: 30 * time.Second,
				},
			}
			srcURI, artifactPath, defaultPGP, pgpSources, assertResult := tt.setup(t, ctx, log, config)

			err := Verify(ctx, log, config, defaultPGP, srcURI, artifactPath, false, pgpSources...)
			logs := obs.FilterMessageSnippet("Skipped remote PGP located at")
			assertResult(t, err, logs.Len(), artifactPath)
			assert.FileExists(t, artifactPath)
			assert.FileExists(t, artifactPath+".sha512")
		})
	}
}

func TestVerifyRemoteRetriesSignatureFetch(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "verifier being tested uses an OpenPGP key which results in a SHA-1 violation.")

	content := []byte("sample content")
	hash := sha512.Sum512(content)
	pub, sig := pgptest.Sign(t, bytes.NewReader(content))
	fileName := verifierTestArtifact.FileName
	files := map[string][]byte{
		"/beats/elastic-agent/" + fileName:             content,
		"/beats/elastic-agent/" + fileName + ".sha512": []byte(fmt.Sprintf("%x %s", hash, fileName)),
	}

	var ascRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/beats/elastic-agent/"+fileName+".asc" {
			ascRequests++
			if ascRequests <= 2 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(sig)
			require.NoError(t, err)
			return
		}

		body, ok := files[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(body)
		require.NoError(t, err)
	}))
	defer server.Close()

	ctx := context.Background()
	log, _ := loggertest.New("TestVerifyRemoteRetriesSignatureFetch")
	targetDir := t.TempDir()
	config := &Config{
		TargetDirectory: targetDir,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: 30 * time.Second,
		},
	}
	srcURI := server.URL + "/beats/elastic-agent/" + fileName
	artifactPath := filepath.Join(config.TargetDirectory, fileName)
	require.NoError(t, download(ctx, log, config, nil, nil, srcURI, artifactPath, defaultFileOps()))
	require.NoError(t, download(ctx, log, config, nil, nil, srcURI+".sha512", artifactPath+".sha512", defaultFileOps()))

	err := Verify(ctx, log, config, pub, srcURI, artifactPath, false)
	require.NoError(t, err)
	require.Equal(t, 3, ascRequests)
}

func TestVerifyRemoteWithProxy(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "verifier being tested uses an OpenPGP key which results in a SHA-1 violation.")

	content := []byte("sample content")
	hash := sha512.Sum512(content)
	pub, sig := pgptest.Sign(t, bytes.NewReader(content))
	fileName := verifierTestArtifact.FileName
	files := map[string][]byte{
		"/beats/elastic-agent/" + fileName:             content,
		"/beats/elastic-agent/" + fileName + ".sha512": []byte(fmt.Sprintf("%x %s", hash, fileName)),
		"/beats/elastic-agent/" + fileName + ".asc":    sig,
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(body)
		require.NoError(t, err)
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

	ctx := context.Background()
	log, _ := loggertest.New("TestVerifyRemoteWithProxy")
	targetDir := t.TempDir()
	config := &Config{
		TargetDirectory: targetDir,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: time.Second,
			Proxy: httpcommon.HTTPClientProxySettings{
				URL: (*httpcommon.ProxyURI)(proxyURL),
			},
		},
	}
	srcURI := brokenServer.URL + "/beats/elastic-agent/" + fileName
	artifactPath := filepath.Join(config.TargetDirectory, fileName)
	require.NoError(t, download(ctx, log, config, nil, nil, srcURI, artifactPath, defaultFileOps()))
	require.NoError(t, download(ctx, log, config, nil, nil, srcURI+".sha512", artifactPath+".sha512", defaultFileOps()))

	err = Verify(ctx, log, config, pub, srcURI, artifactPath, false)
	require.NoError(t, err)
	require.Equal(t, 0, directRequests)
}
