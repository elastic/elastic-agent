// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

func TestReadNotExistingMarkerFile(t *testing.T) {
	testcases := []struct {
		name                string
		setup               func(t *testing.T, tmpDir string) string
		wantMarkerFileBytes []byte
		wantErr             assert.ErrorAssertionFunc
	}{
		{
			name: "No error when containing dir does not exist",
			setup: func(t *testing.T, tmpDir string) string {
				notExistingDataDir := filepath.Join(tmpDir, "data")
				return markerFilePath(notExistingDataDir)
			},
			wantMarkerFileBytes: nil,
			wantErr:             assert.NoError,
		},
		{
			name: "No error when marker file does not exist",
			setup: func(t *testing.T, tmpDir string) string {
				return markerFilePath(tmpDir)
			},
			wantMarkerFileBytes: nil,
			wantErr:             assert.NoError,
		},
		{
			name: "happy path: read marker file bytes",
			setup: func(t *testing.T, tmpDir string) string {
				filePath := markerFilePath(tmpDir)
				err := os.WriteFile(filePath, []byte("foobar"), 0600)
				require.NoError(t, err)
				return filePath
			},
			wantMarkerFileBytes: []byte("foobar"),
			wantErr:             assert.NoError,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			markerFileName := tc.setup(t, tmpDir)
			markerFileBytes, err := readMarkerFile(markerFileName, filelock.NewNoopLocker())
			tc.wantErr(t, err)
			assert.Equal(t, tc.wantMarkerFileBytes, markerFileBytes)
		})
	}
}

func TestWriteMarkerFile(t *testing.T) {
	tmpDir := t.TempDir()
	markerFile := filepath.Join(tmpDir, markerFilename)

	markerBytes := []byte("foo bar")
	err := writeMarkerFile(markerFile, markerBytes, true, noopLocker)
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
	err := writeMarkerFile(testMarkerFile, randomBytes(40), true, noopLocker)
	require.NoError(t, err, "could not write long marker file")

	// Get length of file
	fileInfo, err := os.Stat(testMarkerFile)
	require.NoError(t, err)
	originalSize := fileInfo.Size()

	err = writeMarkerFile(testMarkerFile, randomBytes(25), true, noopLocker)
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

func TestUpdateMarkerFile(t *testing.T) {
	marker := &UpdateMarker{
		Version:           "1.2.3",
		VersionedHome:     "/home",
		Hash:              "sha...hash",
		UpdatedOn:         time.Now(),
		PrevVersion:       "0.1.2",
		PrevHash:          "sha..hash",
		PrevVersionedHome: "/home/elastic",
		Acked:             false,
		Action:            &fleetapi.ActionUpgrade{ActionID: "123", ActionType: "UPGRADAE"},
		Details:           details.NewDetails("1.2.3", details.StateRequested, "action-id"),
		DesiredOutcome:    OUTCOME_UPGRADE,
	}
	tmp := t.TempDir()
	markerFile := filepath.Join(tmp, "marker")
	require.NoError(t, saveMarkerToPath(marker, markerFile, true, noopLocker))

	// update marker
	var wg sync.WaitGroup
	wg.Add(2)

	// first concurrent update
	go func() {
		err := UpdateMarkerFile(markerFile, func(m *UpdateMarker) {
			m.Version = "1.2.3-up"
		})
		assert.NoError(t, err)
		wg.Done()
	}()

	// second update
	go func() {
		err := UpdateMarkerFile(markerFile, func(m *UpdateMarker) {
			m.Hash = "sha...hash2"
		})
		assert.NoError(t, err)
		wg.Done()
	}()

	wg.Wait()

	// Assert
	loadedMarker, err := loadMarker(markerFile, noopLocker)
	assert.NoError(t, err)
	assert.Equal(t, "1.2.3-up", loadedMarker.Version)
	assert.Equal(t, "sha...hash2", loadedMarker.Hash)
	assert.Equal(t, marker.VersionedHome, loadedMarker.VersionedHome)
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
