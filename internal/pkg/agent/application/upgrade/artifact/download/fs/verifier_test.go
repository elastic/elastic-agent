// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fs

import (
	"bytes"
	"context"
	"crypto/sha512"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/pgptest"
)

var testVersion = version.NewParsedSemVer(7, 5, 1, "", "")

var (
	beatSpec = artifact.Artifact{
		Name:     "Elastic Agent",
		Cmd:      "elastic-agent",
		Artifact: "beat/elastic-agent"}
)

func TestFetchVerify(t *testing.T) {
	// See docs/pgp-sign-verify-artifact.md for how to generate a key, export
	// the public key, sign a file and verify it.

	log, _ := logger.New("", false)
	timeout := 15 * time.Second
	dropPath := filepath.Join("testdata", "drop")
	installPath := filepath.Join("testdata", "install")
	targetPath := filepath.Join("testdata", "download")
	ctx := context.Background()
	a := artifact.Artifact{
		Name: "elastic-agent", Cmd: "elastic-agent", Artifact: "beats/elastic-agent"}
	aVersion := version.NewParsedSemVer(8, 0, 0, "", "")

	filename := "elastic-agent-8.0.0-darwin-x86_64.tar.gz"
	targetFilePath := filepath.Join(targetPath, filename)
	hashTargetFilePath := filepath.Join(targetPath, filename+".sha512")
	ascTargetFilePath := filepath.Join(targetPath, filename+".asc")

	// cleanup
	defer os.RemoveAll(targetPath)

	config := &artifact.Config{
		TargetDirectory: targetPath,
		DropPath:        dropPath,
		InstallPath:     installPath,
		OperatingSystem: "darwin",
		Architecture:    "32",
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: timeout,
		},
	}

	err := prepareFetchVerifyTests(dropPath, targetPath, filename, targetFilePath, hashTargetFilePath)
	require.NoError(t, err)

	pgp, err := os.ReadFile(filepath.Join(dropPath, "public-key.pgp"))
	require.NoError(t, err, "could not read public PGP key")
	verifier, err := NewVerifier(log, config, pgp)
	require.NoError(t, err, "could not create the verifier")

	// first download verify should fail:
	// download skipped, as invalid package is prepared upfront
	// verify fails and cleans download
	err = verifier.Verify(a, *aVersion, false)
	var checksumErr *download.ChecksumMismatchError
	require.ErrorAs(t, err, &checksumErr)

	_, err = os.Stat(targetFilePath)
	require.True(t, os.IsNotExist(err))

	_, err = os.Stat(hashTargetFilePath)
	require.True(t, os.IsNotExist(err))

	// second one should pass
	// download not skipped: package missing
	// verify passes because hash is not correct
	_, err = NewDownloader(config).Download(ctx, a, aVersion)
	require.NoError(t, err)
	asc, err := os.ReadFile(filepath.Join(dropPath, filename+".asc"))
	require.NoErrorf(t, err, "could not open .asc for copy")
	err = os.WriteFile(ascTargetFilePath, asc, 0o600)
	require.NoErrorf(t, err, "could not save .asc (%q) to target path (%q)",
		filepath.Join(dropPath, filename+".asc"), ascTargetFilePath)

	// file downloaded ok
	_, err = os.Stat(targetFilePath)
	require.NoError(t, err)
	_, err = os.Stat(hashTargetFilePath)
	require.NoError(t, err)
	_, err = os.Stat(ascTargetFilePath)
	require.NoError(t, err)

	err = verifier.Verify(a, *aVersion, false)
	require.NoError(t, err)

	// Bad GPG public key.
	{
		verifier.defaultKey = []byte("garbage")

		// Don't delete anything.
		assertFileExists(t, targetFilePath)
		assertFileExists(t, targetFilePath+".sha512")
	}

	// Setup proper GPG public key.
	verifier.defaultKey = release.PGP()

	// Missing .asc file.
	{
		err = verifier.Verify(a, *aVersion, false)
		require.Error(t, err)

		// Don't delete these files when GPG validation failure.
		assertFileExists(t, targetFilePath)
		assertFileExists(t, targetFilePath+".sha512")
	}

	// Invalid signature.
	{
		err = os.WriteFile(targetFilePath+".asc", []byte("bad sig"), 0o600)
		require.NoError(t, err)

		err = verifier.Verify(a, *aVersion, false)
		var invalidSigErr *download.InvalidSignatureError
		assert.ErrorAs(t, err, &invalidSigErr)

		// Don't delete these files when GPG validation failure.
		assertFileExists(t, targetFilePath)
		assertFileExists(t, targetFilePath+".sha512")

		// Bad .asc file should be removed.
		assertFileNotExists(t, targetFilePath+".asc")
	}
}

func prepareFetchVerifyTests(
	dropPath,
	targetDir,
	filename,
	targetFilePath,
	hashTargetFilePath string) error {
	sourceFilePath := filepath.Join(dropPath, filename)
	hashSourceFilePath := filepath.Join(dropPath, filename+".sha512")

	// clean targets
	os.Remove(targetFilePath)
	os.Remove(hashTargetFilePath)

	if err := os.MkdirAll(targetDir, 0775); err != nil {
		return err
	}

	sourceFile, err := os.Open(sourceFilePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	targretFile, err := os.OpenFile(targetFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer targretFile.Close()

	hashContent, err := os.ReadFile(hashSourceFilePath)
	if err != nil {
		return err
	}

	corruptedHash := append([]byte{1, 2, 3, 4, 5, 6}, hashContent[6:]...)
	return os.WriteFile(hashTargetFilePath, corruptedHash, 0666)
}

func TestVerify(t *testing.T) {
	tt := []struct {
		Name             string
		RemotePGPUris    []string
		UnreachableCount int
	}{
		{"default", nil, 0},
		{"unreachable local path", []string{download.PgpSourceURIPrefix + "https://127.0.0.1:2874/path/does/not/exist"}, 1},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			log, obs := logger.NewTesting("TestVerify")
			targetDir := t.TempDir()

			timeout := 30 * time.Second

			config := &artifact.Config{
				TargetDirectory: targetDir,
				DropPath:        filepath.Join(targetDir, "drop"),
				OperatingSystem: "linux",
				Architecture:    "32",
				HTTPTransportSettings: httpcommon.HTTPTransportSettings{
					Timeout: timeout,
				},
			}

			pgpKey := prepareTestCase(t, beatSpec, testVersion, config)

			testClient := NewDownloader(config)
			artifactPath, err := testClient.Download(context.Background(), beatSpec, testVersion)
			require.NoError(t, err, "fs.Downloader could not download artifacts")
			_, err = testClient.DownloadAsc(context.Background(), beatSpec, *testVersion)
			require.NoError(t, err, "fs.Downloader could not download artifacts .asc file")

			_, err = os.Stat(artifactPath)
			require.NoError(t, err)

			testVerifier, err := NewVerifier(log, config, pgpKey)
			require.NoError(t, err)

			err = testVerifier.Verify(beatSpec, *testVersion, false, tc.RemotePGPUris...)
			require.NoError(t, err)

			// log message informing remote PGP was skipped
			logs := obs.FilterMessageSnippet("Skipped remote PGP located at")
			require.Equal(t, tc.UnreachableCount, logs.Len())
		})
	}
}

// prepareTestCase creates an artifact file, defined by 'a' and 'testVersion',
// its corresponding checksum (.sha512) and signature (.asc) files.
// It creates the necessary key to sing the artifact and returns the public key
// to verify the signature.
func prepareTestCase(t *testing.T, a artifact.Artifact, aVersion *version.ParsedSemVer, cfg *artifact.Config) []byte {

	filename, err := artifact.GetArtifactName(a, *aVersion, cfg.OperatingSystem, cfg.Architecture)
	require.NoErrorf(t, err, "could not get artifact name")

	err = os.MkdirAll(cfg.DropPath, 0777)
	require.NoErrorf(t, err, "failed creating directory %q", cfg.DropPath)

	filePath := filepath.Join(cfg.DropPath, filename)
	filePathSHA := filePath + ".sha512"
	filePathASC := filePath + ".asc"

	content := []byte("sample content")
	err = os.WriteFile(filePath, content, 0644)
	require.NoErrorf(t, err, "could not write %q file", filePath)

	hash := sha512.Sum512(content)
	hashContent := fmt.Sprintf("%x %s", hash, filename)
	err = os.WriteFile(filePathSHA, []byte(hashContent), 0644)
	require.NoErrorf(t, err, "could not write %q file", filePathSHA)

	pub, sig := pgptest.Sing(t, bytes.NewReader(content))
	err = os.WriteFile(filePathASC, sig, 0644)
	require.NoErrorf(t, err, "could not write %q file", filePathASC)

	return pub
}

func assertFileExists(t testing.TB, path string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.NoError(t, err, "file %s does not exist", path)
}

func assertFileNotExists(t testing.TB, path string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.ErrorIs(t, err, os.ErrNotExist)
}
