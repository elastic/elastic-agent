// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/require"
)

func TestWriteMarkerFile(t *testing.T) {
	tmpDir := t.TempDir()
	markerFile := filepath.Join(tmpDir, markerFilename)

	markerBytes := []byte("foo bar")
	err := writeMarkerFile(markerFile, markerBytes, true)
	require.NoError(t, err)

	data, err := os.ReadFile(markerFile)
	require.NoError(t, err)
	require.Equal(t, markerBytes, data)
}

func TestWriteMarkerFileWithTruncation(t *testing.T) {
	tmpDir := t.TempDir()
	testMarkerFile := filepath.Join(tmpDir, markerFilename)

	// Watch marker file for the duration of this test, to ensure
	// it's never empty (truncated).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error)
	watchFileNotEmpty(t, ctx, testMarkerFile, errCh)
	var watchErr error
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-errCh:
				watchErr = err
			}
		}
	}()

	// Write a long marker file
	t.Logf("writing long marker file: %q", testMarkerFile)
	err := writeMarkerFile(testMarkerFile, randomBytes(40), true)
	t.Logf("wrote long marker file: %q", testMarkerFile)
	require.NoError(t, err)

	// Get length of file
	fileInfo, err := os.Stat(testMarkerFile)
	require.NoError(t, err)
	originalSize := fileInfo.Size()

	// Write a shorter marker file
	t.Logf("writing shorter marker file: %q", testMarkerFile)
	err = writeMarkerFile(testMarkerFile, randomBytes(25), true)
	t.Logf("wrote shorter marker file: %q", testMarkerFile)
	require.NoError(t, err)

	// Get length of file
	fileInfo, err = os.Stat(testMarkerFile)
	require.NoError(t, err)
	newSize := fileInfo.Size()

	// Make sure shorter file has is smaller in length than
	// the original long marker file
	require.Less(t, newSize, originalSize)

	// Cancel watch on marker file now that we're at the end of the test and
	// check that there were no errors.
	cancel()
	require.NoError(t, watchErr)
	close(errCh)
}

func watchFileNotEmpty(t *testing.T, ctx context.Context, filePath string, errCh chan error) {
	watcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)

	dirPath := filepath.Dir(filePath)
	err = watcher.Add(dirPath)
	require.NoError(t, err)

	// Watch file
	go func() {
		defer watcher.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-watcher.Errors:
				if !ok { // Channel was closed (i.e. Watcher.Close() was called).
					errCh <- errors.New("fsnotify.Watcher's error channel was closed")
					return
				}

				errCh <- fmt.Errorf("upgrade marker watch returned error: %w", err)
				continue
			case e, ok := <-watcher.Events:
				if !ok { // Channel was closed (i.e. Watcher.Close() was called).
					errCh <- errors.New("fsnotify.Watcher's events channel was closed")
					return
				}

				if e.Name != filePath {
					// Since we are watching the directory that will contain the file, we
					// could receive events here for changes to files other than the file we're
					// interested in. We ignore such events.
					continue
				}

				switch {
				case e.Op&(fsnotify.Create|fsnotify.Write) != 0:
					// File was created or updated; read its length
					// and send error if it's zero
					fileInfo, err := os.Stat(filePath)
					if err != nil {
						errCh <- fmt.Errorf("failed to stat file [%s]: %w", filePath, err)
					}

					if fileInfo.Size() == 0 {
						errCh <- fmt.Errorf("file [%s] has size 0", filePath)
					}
				}
			}
		}
	}()
}

func randomBytes(length int) []byte {
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ" +
		"abcdefghijklmnopqrstuvwxyzåäö" +
		"0123456789" +
		"~=+%^*/()[]{}/!@#$?|")

	var b []byte
	for i := 0; i < length; i++ {
		rune := chars[rand.Intn(len(chars))]
		b = append(b, byte(rune))
	}

	return b
}
