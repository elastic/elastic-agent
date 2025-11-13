// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// LogFile wraps a *os.File and makes it more suitable for tests.
// Key features:
//   - On failures, the file is kept and its path printed
//   - Methods to search and wait for substrings in lines are provided,
//     they keep track of the offset, ensuring ordering when
//     when searching.
type LogFile struct {
	*os.File
	offset               int64
	KeepLogFileOnSuccess bool
}

// NewLogFile returns a new LogFile, path must be the components of a path,
// they will be joined using the OS path separator.
// If path is not provided, os.TempDir is used as the base path for the file.
func NewLogFile(t testing.TB, path ...string) *LogFile {
	dir := filepath.Join(path...)
	if dir == "" {
		dir = os.TempDir()
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("cannot create folder for logs: %s", err)
	}

	f, err := os.CreateTemp(dir, "elastic-agent-*.ndjson")
	if err != nil {
		t.Fatalf("cannot create log file: %s", err)
	}

	lf := &LogFile{
		File: f,
	}

	t.Cleanup(func() {
		if err := f.Sync(); err != nil {
			t.Logf("cannot sync log file: %s", err)
		}

		if err := f.Close(); err != nil {
			t.Logf("cannot close log file: %s", err)
		}

		// If the test failed, print the log file location,
		// otherwise remove it.
		if t.Failed() || lf.KeepLogFileOnSuccess {
			t.Logf("Full logs written to %s", f.Name())
			return
		}

		if err := os.Remove(f.Name()); err != nil {
			t.Logf("could not remove temporary log file: %s", err)
		}
	})

	return lf
}

// WaitLogsContains waits for the specified string s to be present in the logs within
// the given timeout duration and fails the test if s is not found.
// It keeps track of the log file offset, reading only new lines. Each
// subsequent call to WaitLogsContains will only check logs not yet evaluated.
// msgAndArgs should be a format string and arguments that will be printed
// if the logs are not found, providing additional context for debugging.
func (l *LogFile) WaitLogsContains(t testing.TB, s string, timeout time.Duration, msgAndArgs ...any) {
	t.Helper()
	require.EventuallyWithT(
		t,
		func(c *assert.CollectT) {
			found, err := l.FindInLogs(s)
			if err != nil {
				c.Errorf("cannot check the log file: %s", err)
				return
			}

			if !found {
				c.Errorf("did not find '%s' in the logs", s)
			}
		},
		timeout,
		100*time.Millisecond,
		msgAndArgs...)
}

// LogContains searches for str in the log file keeping track of the
// offset. If there is any issue reading the log file, then t.Fatalf is called,
// if str is not present in the logs, t.Errorf is called.
func (l *LogFile) LogContains(t testing.TB, str string) {
	t.Helper()
	found, err := l.FindInLogs(str)
	if err != nil {
		t.Fatalf("cannot read log file: %s", err)
	}

	if !found {
		t.Errorf("'%s' not found in logs", str)
	}
}

// FindInLogs searches for str in the log file keeping track of the offset.
// It returns true if str is found in the logs. If there are any errors,
// it returns false and the error
func (l *LogFile) FindInLogs(str string) (bool, error) {
	// Open the file again so we can seek and not interfere with
	// the logger writing to it.
	f, err := os.Open(l.Name())
	if err != nil {
		return false, fmt.Errorf("cannot open log file for reading: %w", err)
	}

	if _, err := f.Seek(l.offset, io.SeekStart); err != nil {
		return false, fmt.Errorf("cannot seek log file: %w", err)
	}

	r := bufio.NewReader(f)
	for {
		data, err := r.ReadBytes('\n')
		line := string(data)
		l.offset += int64(len(data))

		if err != nil {
			if !errors.Is(err, io.EOF) {
				return false, fmt.Errorf("error reading log file '%s': %w", l.Name(), err)
			}
			break
		}

		if strings.Contains(line, str) {
			return true, nil
		}
	}

	return false, nil
}

// ResetOffset resets the log file offset
func (l *LogFile) ResetOffset() {
	l.offset = 0
}
