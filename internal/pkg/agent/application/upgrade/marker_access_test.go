// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"testing"

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
	var wg sync.WaitGroup
	wg.Add(1)
	watchFileNotEmpty(t, ctx, testMarkerFile, errCh, &wg)
	var watchErr error

	var lsWg sync.WaitGroup
	lsWg.Add(1)
	lsCtx, lsCancel := context.WithCancel(context.Background())
	defer lsCancel()
	go func() {
		defer lsWg.Done()
		for {
			select {
			case <-lsCtx.Done():
				return
			case err := <-errCh:
				watchErr = err
			}
		}
	}()

	// Write a long marker file
	err := writeMarkerFile(testMarkerFile, randomBytes(40), true)
	require.NoError(t, err, "could not write long marker file")

	// Get length of file
	fileInfo, err := os.Stat(testMarkerFile)
	require.NoError(t, err)
	originalSize := fileInfo.Size()

	err = writeMarkerFile(testMarkerFile, randomBytes(25), true)
	require.NoError(t, err)

	// Get length of file
	fileInfo, err = os.Stat(testMarkerFile)
	require.NoError(t, err)
	newSize := fileInfo.Size()

	// Make sure shorter file is smaller than the original long marker file.
	require.Less(t, newSize, originalSize)

	// Cancel watch on marker file now that we're at the end of the test and
	// check that there were no errors.
	cancel()
	wg.Wait()

	// Now that the watcher Go routine is cancelled and exited, cancel the listener that listens on errCh
	lsCancel()
	lsWg.Wait()

	require.NoError(t, watchErr)

	close(errCh)
}

func watchFileNotEmpty(t *testing.T, ctx context.Context, filePath string, errCh chan error, wg *sync.WaitGroup) {
	watcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)

	dirPath := filepath.Dir(filePath)
	err = watcher.Add(dirPath)
	require.NoError(t, err)

	// Watch file
	go func() {
		defer wg.Done()
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
						return
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
		rune := chars[rand.IntN(len(chars))]
		b = append(b, byte(rune))
	}

	return b
}
