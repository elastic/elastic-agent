// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package downloads

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestDownloadFile(t *testing.T) {
	s := httptest.NewServer(http.FileServer(http.Dir("./testdata")))
	t.Cleanup(s.Close)

	var dRequest = downloadRequest{
		URL: fmt.Sprintf("http://%s/some-file.txt",
			s.Listener.Addr().String()),
		TargetPath: filepath.Join(t.TempDir(), "some-file.txt"),
	}

	err := downloadFile(&dRequest)
	assert.Nil(t, err)
	assert.FileExistsf(t, dRequest.TargetPath, "file should exist")
}

func TestVerifyChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	content := "hello world"
	hashBytes := sha512.Sum512([]byte(content))
	hashHex := hex.EncodeToString(hashBytes[:])

	t.Run("valid checksum", func(t *testing.T) {
		// Write the file to be verified
		fileName := "testfile.txt"
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, fileName), []byte(content), 0644))

		// Write the checksum file
		checksumContent := fmt.Sprintf("%s %s", hashHex, fileName)
		checksumPath := filepath.Join(tmpDir, "checksum.txt")
		require.NoError(t, os.WriteFile(checksumPath, []byte(checksumContent), 0644))

		// Run test
		err := verifyChecksum(checksumPath)
		assert.NoError(t, err)
	})

	t.Run("missing checksum file", func(t *testing.T) {
		err := verifyChecksum(filepath.Join(tmpDir, "missing.txt"))
		assert.ErrorContains(t, err, "failed to read checksum file")
	})

	t.Run("malformed checksum content", func(t *testing.T) {
		checksumPath := filepath.Join(tmpDir, "badchecksum.txt")
		require.NoError(t, os.WriteFile(checksumPath, []byte("invalid-format-line"), 0644))

		err := verifyChecksum(checksumPath)
		assert.ErrorContains(t, err, "invalid format")
	})

	t.Run("missing target file", func(t *testing.T) {
		checksumContent := fmt.Sprintf("%s %s", hashHex, "nonexistent.txt")
		checksumPath := filepath.Join(tmpDir, "checksum_missing_target.txt")
		require.NoError(t, os.WriteFile(checksumPath, []byte(checksumContent), 0644))

		err := verifyChecksum(checksumPath)
		assert.ErrorContains(t, err, "failed to open file for sha512 summing")
	})

	t.Run("checksum mismatch", func(t *testing.T) {
		invalidContent := content + "x"
		fileName := "file.txt"
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, fileName), []byte(invalidContent), 0644))
		checksumContent := fmt.Sprintf("%s %s", hashHex, fileName)
		checksumPath := filepath.Join(tmpDir, "badhash.txt")
		require.NoError(t, os.WriteFile(checksumPath, []byte(checksumContent), 0644))

		err := verifyChecksum(checksumPath)
		assert.ErrorContains(t, err, "does not match expected checksum")
	})
}
