// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fs

import (
	"context"
	"crypto/sha512"
	"fmt"
	"io/ioutil"
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
)

const (
	version = "7.5.1"
)

var (
	beatSpec = artifact.Artifact{Name: "Filebeat", Cmd: "filebeat", Artifact: "beat/filebeat"}
)

func TestFetchVerify(t *testing.T) {
	log, _ := logger.New("", false)
	timeout := 15 * time.Second
	dropPath := filepath.Join("testdata", "drop")
	installPath := filepath.Join("testdata", "install")
	targetPath := filepath.Join("testdata", "download")
	ctx := context.Background()
	s := artifact.Artifact{Name: "Beat", Cmd: "beat", Artifact: "beats/filebeat"}
	version := "8.0.0"

	targetFilePath := filepath.Join(targetPath, "beat-8.0.0-darwin-x86_64.tar.gz")
	hashTargetFilePath := filepath.Join(targetPath, "beat-8.0.0-darwin-x86_64.tar.gz.sha512")

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

	err := prepareFetchVerifyTests(dropPath, targetPath, targetFilePath, hashTargetFilePath)
	assert.NoError(t, err)

	downloader := NewDownloader(config)
	verifier, err := NewVerifier(log, config, true, nil)
	assert.NoError(t, err)

	// first download verify should fail:
	// download skipped, as invalid package is prepared upfront
	// verify fails and cleans download
	err = verifier.Verify(s, version, false)
	var checksumErr *download.ChecksumMismatchError
	assert.ErrorAs(t, err, &checksumErr)

	_, err = os.Stat(targetFilePath)
	assert.True(t, os.IsNotExist(err))

	_, err = os.Stat(hashTargetFilePath)
	assert.True(t, os.IsNotExist(err))

	// second one should pass
	// download not skipped: package missing
	// verify passes because hash is not correct
	_, err = downloader.Download(ctx, s, version)
	assert.NoError(t, err)

	// file downloaded ok
	_, err = os.Stat(targetFilePath)
	assert.NoError(t, err)

	_, err = os.Stat(hashTargetFilePath)
	assert.NoError(t, err)

	err = verifier.Verify(s, version, false)
	assert.NoError(t, err)

	// Enable GPG signature validation.
	verifier.allowEmptyPgp = false

	// Bad GPG public key.
	{
		verifier.pgpBytes = []byte("garbage")

		// Don't delete anything.
		assertFileExists(t, targetFilePath)
		assertFileExists(t, targetFilePath+".sha512")
	}

	// Setup proper GPG public key.
	_, verifier.pgpBytes = release.PGP()

	// Missing .asc file.
	{
		err = verifier.Verify(s, version, false)
		require.Error(t, err)

		// Don't delete these files when GPG validation failure.
		assertFileExists(t, targetFilePath)
		assertFileExists(t, targetFilePath+".sha512")
	}

	// Invalid signature.
	{
		err = ioutil.WriteFile(targetFilePath+".asc", []byte("bad sig"), 0o600)
		require.NoError(t, err)

		err = verifier.Verify(s, version, false)
		var invalidSigErr *download.InvalidSignatureError
		assert.ErrorAs(t, err, &invalidSigErr)

		// Don't delete these files when GPG validation failure.
		assertFileExists(t, targetFilePath)
		assertFileExists(t, targetFilePath+".sha512")

		// Bad .asc file should be removed.
		assertFileNotExists(t, targetFilePath+".asc")
	}
}

func prepareFetchVerifyTests(dropPath, targetDir, targetFilePath, hashTargetFilePath string) error {
	sourceFilePath := filepath.Join(dropPath, "beat-8.0.0-darwin-x86_64.tar.gz")
	hashSourceFilePath := filepath.Join(dropPath, "beat-8.0.0-darwin-x86_64.tar.gz.sha512")

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

	hashContent, err := ioutil.ReadFile(hashSourceFilePath)
	if err != nil {
		return err
	}

	corruptedHash := append([]byte{1, 2, 3, 4, 5, 6}, hashContent[6:]...)
	return ioutil.WriteFile(hashTargetFilePath, corruptedHash, 0666)
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
			targetDir, err := ioutil.TempDir(os.TempDir(), "")
			require.NoError(t, err)

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

			err = prepareTestCase(beatSpec, version, config)
			require.NoError(t, err)

			testClient := NewDownloader(config)
			artifact, err := testClient.Download(context.Background(), beatSpec, version)
			require.NoError(t, err)

			t.Cleanup(func() {
				os.Remove(artifact)
				os.Remove(artifact + ".sha512")
				os.RemoveAll(config.DropPath)
			})

			_, err = os.Stat(artifact)
			require.NoError(t, err)

			testVerifier, err := NewVerifier(log, config, true, nil)
			require.NoError(t, err)

			err = testVerifier.Verify(beatSpec, version, false, tc.RemotePGPUris...)
			require.NoError(t, err)

			// log message informing remote PGP was skipped
			logs := obs.FilterMessageSnippet("Skipped remote PGP located at")
			require.Equal(t, tc.UnreachableCount, logs.Len())
		})
	}
}

func prepareTestCase(a artifact.Artifact, version string, cfg *artifact.Config) error {
	filename, err := artifact.GetArtifactName(a, version, cfg.OperatingSystem, cfg.Architecture)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.DropPath, 0777); err != nil {
		return err
	}

	content := []byte("sample content")
	hash := sha512.Sum512(content)
	hashContent := fmt.Sprintf("%x %s", hash, filename)

	if err := ioutil.WriteFile(filepath.Join(cfg.DropPath, filename), content, 0644); err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(cfg.DropPath, filename+".sha512"), []byte(hashContent), 0644)
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
