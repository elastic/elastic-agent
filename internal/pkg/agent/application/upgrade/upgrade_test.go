// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func Test_CopyFile(t *testing.T) {
	tt := []struct {
		Name        string
		From        string
		To          string
		IgnoreErr   bool
		KeepOpen    bool
		ExpectedErr bool
	}{
		{
			"Existing, no onerr",
			"test/case1/README.md",
			"test/case1/copy/README.md",
			false,
			false,
			false,
		},
		{
			"Existing but open",
			"test/case2/README.md",
			"test/case2/copy/README.md",
			false,
			true,
			runtime.GOOS == "windows", // this fails only on,
		},
		{
			"Existing but open, ignore errors",
			"test/case3/README.md",
			"test/case3/copy/README.md",
			true,
			true,
			false,
		},
		{
			"Not existing, accept errors",
			"test/case4/README.md",
			"test/case4/copy/README.md",
			false,
			false,
			true,
		},
		{
			"Not existing, ignore errors",
			"test/case5/README.md",
			"test/case5/copy/README.md",
			true,
			false,
			false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			defer func() {
				// cleanup
				_ = os.RemoveAll(filepath.Dir(tc.To))
			}()

			if tc.KeepOpen {
				f, err := os.Open(tc.From)
				require.NoError(t, err)

				defer f.Close()
			}

			l, _ := logger.New("test", false)
			err := copyDir(l, tc.From, tc.To, tc.IgnoreErr)
			require.Equal(t, tc.ExpectedErr, err != nil)
		})
	}
}

func TestShutdownCallback(t *testing.T) {
	l, _ := logger.New("test", false)
	tmpDir, err := ioutil.TempDir("", "shutdown-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// make homepath agent consistent (in a form of elastic-agent-hash)
	homePath := filepath.Join(tmpDir, fmt.Sprintf("%s-%s", agentName, release.ShortCommit()))

	filename := "file.test"
	newCommit := "abc123"
	sourceVersion := "7.14.0"
	targetVersion := "7.15.0"

	content := []byte("content")
	newHome := strings.ReplaceAll(homePath, release.ShortCommit(), newCommit)
	sourceDir := filepath.Join(homePath, "run", "default", "process-"+sourceVersion)
	targetDir := filepath.Join(newHome, "run", "default", "process-"+targetVersion)

	require.NoError(t, os.MkdirAll(sourceDir, 0755))
	require.NoError(t, os.MkdirAll(targetDir, 0755))

	cb := shutdownCallback(l, homePath, sourceVersion, targetVersion, newCommit)

	oldFilename := filepath.Join(sourceDir, filename)
	err = ioutil.WriteFile(oldFilename, content, 0640)
	require.NoError(t, err, "preparing file failed")

	err = cb()
	require.NoError(t, err, "callback failed")

	newFilename := filepath.Join(targetDir, filename)
	newContent, err := ioutil.ReadFile(newFilename)
	require.NoError(t, err, "reading file failed")
	require.Equal(t, content, newContent, "contents are not equal")
}
