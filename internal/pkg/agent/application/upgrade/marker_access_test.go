// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
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

	// it seems the watcher accessing the file is preventing the marker file to
	// be written. 'writeMarkerFile' is constantly failing with "The process
	// cannot access the file because it is being used by another process."
	//
	// TODO(AndersonQ|ycombinator): is it rally necessary to have this watcher?
	//
	// Watch marker file for the duration of this test, to ensure
	// it's never empty (truncated).
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()
	// errCh := make(chan error)
	// watchFileNotEmpty(t, ctx, testMarkerFile, errCh)
	// var watchErr error
	// go func() {
	// 	for {
	// 		select {
	// 		case <-ctx.Done():
	// 			return
	// 		case err := <-errCh:
	// 			watchErr = err
	// 		}
	// 	}
	// }()

	// Write a long marker file
	t.Log("marker file path:", testMarkerFile)
	t.Log("writing long marker file")
	err := writeMarkerFile(testMarkerFile, randomBytes(40), true)
	t.Log("after writing long marker file")
	// If the marker file isn't listed in openfiles, it might be free now,
	// therefore, try again.
	if err != nil && !inOpenfiles(t, testMarkerFile) {
		t.Logf("not inOpenfiles, trying once more")
		err = writeMarkerFile(testMarkerFile, randomBytes(40), true)
	}
	require.NoError(t, err, "could not write long marker file")

	// Get length of file
	fileInfo, err := os.Stat(testMarkerFile)
	require.NoError(t, err)
	originalSize := fileInfo.Size()

	// Write a shorter marker file
	t.Log("writing shorter marker file")
	err = writeMarkerFile(testMarkerFile, randomBytes(25), true)
	t.Log("after writing shorter marker file")
	// If the marker file isn't listed in openfiles, it might be free now,
	// therefore, try again.
	if err != nil && !inOpenfiles(t, testMarkerFile) {
		t.Logf("not inOpenfiles, trying once more")
		err = writeMarkerFile(testMarkerFile, randomBytes(25), true)
	}
	require.NoError(t, err)

	// Get length of file
	fileInfo, err = os.Stat(testMarkerFile)
	require.NoError(t, err)
	newSize := fileInfo.Size()

	// Make sure shorter file is smaller than the original long marker file.
	require.Less(t, newSize, originalSize)

	// // Cancel watch on marker file now that we're at the end of the test and
	// // check that there were no errors.
	// cancel()
	// require.NoError(t, watchErr)
	// close(errCh)
}

// inOpenfiles uses Windows 'openfiles' program to try to find out which
// process is using 'file'. It returns true if found, false otherwise. It also
// returns false if the platform isn't Windows or `openfiles` isn't found.
func inOpenfiles(t *testing.T, file string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	openfiles, err := exec.LookPath("openfiles")
	if err != nil {
		t.Logf("did not fing openfiles to debug what proces is accessing the marker file: %v", err)
		return false
	}

	// docs: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/openfiles
	cmd := exec.Command(openfiles, "/query", "/fo", "csv")
	output, err := cmd.Output()
	if err != nil {
		t.Logf("failed running openfiles: Err: %v, Output: %q", err, output)
		var errExit *exec.ExitError
		if errors.As(err, &errExit) && len(errExit.Stderr) > 0 {
			t.Logf("failed running openfiles: stderr: %s", errExit.Stderr)
		}
		return false
	}

	lines := strings.Split(string(output), "\n")
	var found bool
	for _, line := range lines {
		// check if the line is about the marker file
		if strings.Contains(line, file) {
			found = true
			t.Log("openfiles output about the marker file\n", line)
		}
	}

	if !found {
		t.Logf("openfiles called, but nothing about %q was found",
			file)
		t.Log("openfiles output:")
		t.Log(output)
	}

	return found
}

// func watchFileNotEmpty(t *testing.T, ctx context.Context, filePath string, errCh chan error) {
// 	watcher, err := fsnotify.NewWatcher()
// 	require.NoError(t, err)
//
// 	dirPath := filepath.Dir(filePath)
// 	err = watcher.Add(dirPath)
// 	require.NoError(t, err)
//
// 	// Watch file
// 	go func() {
// 		defer watcher.Close()
// 		for {
// 			select {
// 			case <-ctx.Done():
// 				return
// 			case err, ok := <-watcher.Errors:
// 				if !ok { // Channel was closed (i.e. Watcher.Close() was called).
// 					errCh <- errors.New("fsnotify.Watcher's error channel was closed")
// 					return
// 				}
//
// 				errCh <- fmt.Errorf("upgrade marker watch returned error: %w", err)
// 				continue
// 			case e, ok := <-watcher.Events:
// 				if !ok { // Channel was closed (i.e. Watcher.Close() was called).
// 					errCh <- errors.New("fsnotify.Watcher's events channel was closed")
// 					return
// 				}
//
// 				if e.Name != filePath {
// 					// Since we are watching the directory that will contain the file, we
// 					// could receive events here for changes to files other than the file we're
// 					// interested in. We ignore such events.
// 					continue
// 				}
//
// 				switch {
// 				case e.Op&(fsnotify.Create|fsnotify.Write) != 0:
// 					// File was created or updated; read its length
// 					// and send error if it's zero
// 					fileInfo, err := os.Stat(filePath)
// 					if err != nil {
// 						errCh <- fmt.Errorf("failed to stat file [%s]: %w", filePath, err)
// 					}
//
// 					if fileInfo.Size() == 0 {
// 						errCh <- fmt.Errorf("file [%s] has size 0", filePath)
// 					}
// 				}
// 			}
// 		}
// 	}()
// }

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
