// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

const (
	line1 = "first"
	line2 = "second"
	line3 = "third"
	file  = "elastic-agent-20230530.ndjson"
	file1 = "elastic-agent-20230530-1.ndjson"
	file2 = "elastic-agent-20230530-2.ndjson"
	file3 = "elastic-agent-20230530-3.ndjson"
)

type testFile struct {
	name    string
	content string
}

// just wraps the whole line in exclamation marks
func exclamationModifier(msg []byte) []byte {
	if len(msg) == 0 {
		return msg
	}
	newMsg := make([]byte, len(msg)+2)
	newMsg[0] = '!'
	copy(newMsg[1:len(newMsg)-1], msg)
	newMsg[len(newMsg)-1] = '!'
	return newMsg
}

func TestGetLogFilenames(t *testing.T) {
	t.Run("returns the correct sorted filelist", func(t *testing.T) {
		dir := t.TempDir()

		createFileEmpty(t, dir, file2)
		createFileEmpty(t, dir, file)
		createFileEmpty(t, dir, file1)
		createFileEmpty(t, dir, file3)

		names, err := getLogFilenames(dir)
		require.NoError(t, err)
		expected := []string{
			filepath.Join(dir, file),
			filepath.Join(dir, file1),
			filepath.Join(dir, file2),
			filepath.Join(dir, file3),
		}
		require.Equal(t, expected, names)
	})

	t.Run("returns the correct sorted filelist for multi-day logs", func(t *testing.T) {
		dir := t.TempDir()

		prevDayFile := "elastic-agent-20230529.ndjson"
		prevDayFile1 := "elastic-agent-20230529-1.ndjson"
		prevDayFile2 := "elastic-agent-20230529-2.ndjson"
		prevDayFile3 := "elastic-agent-20230529-3.ndjson"

		createFileEmpty(t, dir, file2)
		createFileEmpty(t, dir, file)
		createFileEmpty(t, dir, prevDayFile1)
		createFileEmpty(t, dir, file1)
		createFileEmpty(t, dir, prevDayFile)
		createFileEmpty(t, dir, prevDayFile2)
		createFileEmpty(t, dir, file3)
		createFileEmpty(t, dir, prevDayFile3)

		names, err := getLogFilenames(dir)
		require.NoError(t, err)
		expected := []string{
			filepath.Join(dir, prevDayFile),
			filepath.Join(dir, prevDayFile1),
			filepath.Join(dir, prevDayFile2),
			filepath.Join(dir, prevDayFile3),
			filepath.Join(dir, file),
			filepath.Join(dir, file1),
			filepath.Join(dir, file2),
			filepath.Join(dir, file3),
		}
		require.Equal(t, expected, names)
	})

	t.Run("does not return directory entries", func(t *testing.T) {
		dir := t.TempDir()
		err := os.Mkdir(filepath.Join(dir, "should_exclude"), 0777)
		require.NoError(t, err)

		names, err := getLogFilenames(dir)
		require.NoError(t, err)
		expected := []string{}
		require.Equal(t, expected, names)
	})

	t.Run("does not return non-log entries", func(t *testing.T) {
		dir := t.TempDir()
		createFileEmpty(t, dir, "excluded")

		names, err := getLogFilenames(dir)
		require.NoError(t, err)
		expected := []string{}
		require.Equal(t, expected, names)
	})

	t.Run("returns a list of one", func(t *testing.T) {
		dir := t.TempDir()
		createFileEmpty(t, dir, file1)

		names, err := getLogFilenames(dir)
		require.NoError(t, err)
		expected := []string{
			filepath.Join(dir, file1),
		}
		require.Equal(t, expected, names)
	})
}

func TestSortLogFilenames(t *testing.T) {
	list := []string{
		"elastic-agent-20230529.ndjson",
		"elastic-agent-20230529-1.ndjson",
		"elastic-agent-20230528.ndjson",
		"elastic-agent-20230529-3.ndjson",
		"elastic-agent-20230529-2.ndjson",
		"elastic-agent-20230530-2.ndjson",
		"elastic-agent-20230530-1.ndjson",
		"elastic-agent-20230530.ndjson",
		"elastic-agent-20230528-1.ndjson",
	}
	expected := []string{
		"elastic-agent-20230528.ndjson",
		"elastic-agent-20230528-1.ndjson",
		"elastic-agent-20230529.ndjson",
		"elastic-agent-20230529-1.ndjson",
		"elastic-agent-20230529-2.ndjson",
		"elastic-agent-20230529-3.ndjson",
		"elastic-agent-20230530.ndjson",
		"elastic-agent-20230530-1.ndjson",
		"elastic-agent-20230530-2.ndjson",
	}
	sortLogFilenames(list)
	require.Equal(t, expected, list)
}

func TestPrintLogs(t *testing.T) {
	cases := []struct {
		name     string
		files    []testFile
		lines    int
		expected string
	}{
		{
			name:     "outputs no lines if there are no log files",
			lines:    100,
			expected: "",
		},
		{
			name: "outputs max number of lines from a single file",
			files: []testFile{
				{
					name:    file1,
					content: generateLines(line1, 1, 20),
				},
			},
			lines:    100,
			expected: generateLines(line1, 1, 20),
		},
		{
			name: "outputs last N lines from the last file only",
			files: []testFile{
				// not ordered on purpose
				{
					name:    file2,
					content: generateLines(line2, 1, 20),
				},
				{
					name:    file3,
					content: generateLines(line3, 1, 30),
				},
				{
					name:    file1,
					content: generateLines(line1, 1, 10),
				},
			},
			lines:    15,
			expected: generateLines(line3, 16, 30),
		},
		{
			name: "outputs last N lines from 2 files gluing them together",
			files: []testFile{
				// not ordered on purpose
				{
					name:    file2,
					content: generateLines(line2, 1, 20),
				},
				{
					name:    file3,
					content: generateLines(line3, 1, 30),
				},
				{
					name:    file1,
					content: generateLines(line1, 1, 10),
				},
			},
			lines:    40,
			expected: generateLines(line2, 11, 20) + generateLines(line3, 1, 30),
		},
		{
			name: "outputs all lines from all files gluing them together",
			files: []testFile{
				// not ordered on purpose
				{
					name:    file2,
					content: generateLines(line2, 1, 20),
				},
				{
					name:    file3,
					content: generateLines(line3, 1, 30),
				},
				{
					name:    file1,
					content: generateLines(line1, 1, 10),
				},
			},
			lines:    100,
			expected: generateLines(line1, 1, 10) + generateLines(line2, 1, 20) + generateLines(line3, 1, 30),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range tc.files {
				createFileContent(t, dir, f.name, bytes.NewBuffer([]byte(f.content)))
			}
			result := bytes.NewBuffer(nil)
			err := printLogs(context.Background(), result, dir, tc.lines, false, nil, nil)
			require.NoError(t, err)

			require.Equal(t, tc.expected, result.String())
		})
	}

	t.Run("returns tail and then follows the logs", func(t *testing.T) {
		dir := t.TempDir()
		createFileContent(t, dir, file1, bytes.NewBuffer([]byte(generateLines(line1, 1, 10))))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		logResult := newChanWriter()
		errChan := make(chan error)
		go func() {
			errChan <- printLogs(ctx, logResult, dir, 5, true, nil, nil)
		}()

		var expected string
		t.Run("tails the file", func(t *testing.T) {
			expected = generateLines(line1, 6, 10)
			logResult.waitUntilMatch(t, expected, time.Second)
		})

		t.Run("detects new lines and prints them", func(t *testing.T) {
			f, err := os.OpenFile(filepath.Join(dir, file1), os.O_WRONLY|os.O_APPEND, 0)
			require.NoError(t, err)
			_, err = f.WriteString(generateLines(line1, 11, 20))
			require.NoError(t, err)
			f.Close()

			expected += generateLines(line1, 11, 20)
			logResult.waitUntilMatch(t, expected, 3*watchInterval)
		})

		t.Run("detects a new file and switches to it", func(t *testing.T) {
			createFileContent(t, dir, file2, bytes.NewBuffer([]byte(generateLines(line2, 1, 20))))

			expected += generateLines(line2, 1, 20)
			logResult.waitUntilMatch(t, expected, 3*watchInterval)
		})

		t.Run("detects another file and switches to it", func(t *testing.T) {
			createFileContent(t, dir, file3, bytes.NewBuffer([]byte(generateLines(line3, 1, 30))))

			expected += generateLines(line3, 1, 30)
			logResult.waitUntilMatch(t, expected, 3*watchInterval)
		})

		t.Run("handles interruption correctly", func(t *testing.T) {
			cancel()
			select {
			case err := <-errChan:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				require.FailNow(t, "context must stop logs following")
			}
		})
	})

	t.Run("returns tail and then follows the logs with filter and modifier", func(t *testing.T) {
		dir := t.TempDir()
		content := []byte(`{"component":{"id":"match"}, "message":"test1"}
{"component":{"id":"non-match"}, "message":"test2"}
{"component":{"id":"match"}, "message":"test3"}
{"component":{"id":"match"}, "message":"test4"}
{"component":{"id":"non-match"}, "message":"test5"}
{"component":{"id":"match"}, "message":"test6"}
`)

		createFileContent(t, dir, file1, bytes.NewBuffer(content))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		logResult := newChanWriter()
		errChan := make(chan error)
		go func() {
			errChan <- printLogs(ctx, logResult, dir, 3, true, createComponentFilter("match"), exclamationModifier)
		}()

		var expected string

		t.Run("tails filtering the file", func(t *testing.T) {
			expected = `!{"component":{"id":"match"}, "message":"test3"}!
!{"component":{"id":"match"}, "message":"test4"}!
!{"component":{"id":"match"}, "message":"test6"}!
`
			logResult.waitUntilMatch(t, expected, time.Second)
		})

		t.Run("detects new lines and prints them with filter", func(t *testing.T) {
			f, err := os.OpenFile(filepath.Join(dir, file1), os.O_WRONLY|os.O_APPEND, 0)
			require.NoError(t, err)

			content := `{"component":{"id":"match"}, "message":"test7"}
{"component":{"id":"non-match"}, "message":"test8"}
{"component":{"id":"match"}, "message":"test9"}
{"component":{"id":"match"}, "message":"test10"}
{"component":{"id":"non-match"}, "message":"test11"}
{"component":{"id":"match"}, "message":"test12"}
`

			_, err = f.WriteString(content)
			require.NoError(t, err)
			f.Close()

			time.Sleep(watchInterval)

			expected += `!{"component":{"id":"match"}, "message":"test7"}!
!{"component":{"id":"match"}, "message":"test9"}!
!{"component":{"id":"match"}, "message":"test10"}!
!{"component":{"id":"match"}, "message":"test12"}!
`

			logResult.waitUntilMatch(t, expected, 2*watchInterval)
		})

		t.Run("detects a new file and switches to it with filter", func(t *testing.T) {
			content := `{"component":{"id":"match"}, "message":"test13"}
{"component":{"id":"non-match"}, "message":"test14"}
{"component":{"id":"match"}, "message":"test15"}
`

			createFileContent(t, dir, file2, bytes.NewBuffer([]byte(content)))

			time.Sleep(watchInterval)

			expected += `!{"component":{"id":"match"}, "message":"test13"}!
!{"component":{"id":"match"}, "message":"test15"}!
`

			logResult.waitUntilMatch(t, expected, 2*watchInterval)
		})

		t.Run("handles interruption correctly", func(t *testing.T) {
			cancel()
			select {
			case err := <-errChan:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				require.FailNow(t, "context must stop logs following")
			}
		})
	})
}

func TestPrintLogFile(t *testing.T) {
	testBufferSize := 64
	cases := []struct {
		name      string
		fileLines int
		lines     int
		expLines  int
		expected  string
	}{
		{
			name:      "outputs no lines if the file is empty",
			fileLines: 0,
			lines:     100,
			expLines:  0,
			expected:  "",
		},
		{
			name:      "outputs max number lines from a single file that fits in the buffer",
			fileLines: 5,
			lines:     100,
			expLines:  5,
			expected:  generateLines(line1, 1, 5),
		},
		{
			name:      "outputs number lines from a single file that fits in the buffer",
			fileLines: 5,
			lines:     3,
			expLines:  3,
			expected:  generateLines(line1, 3, 5),
		},
		{
			name:      "outputs number lines from a single file that does not fit in the buffer",
			fileLines: 500,
			lines:     400,
			expLines:  400,
			expected:  generateLines(line1, 101, 500),
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			content := ""
			if tc.fileLines > 0 {
				content = generateLines(line1, 1, tc.fileLines)
			}

			filename := fmt.Sprintf("test-%d", i)
			createFileContent(t, dir, filename, bytes.NewBuffer([]byte(content)))

			sw := &stackWriter{}

			buf := make([]byte, testBufferSize)

			printed, err := printLogFile(filepath.Join(dir, filename), tc.lines, sw, buf)
			require.NoError(t, err)

			result := bytes.NewBuffer(nil)
			err = sw.PopAll(result)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.String())
			assert.Equal(t, tc.expLines, printed)
		})
	}

	matchingEntry := []byte(`{"component":{"id":"testID"}}` + "\n")
	nonMatchingEntry := []byte(`{"component":{"id":"NO_MATCH"}}` + "\n")
	matchingID := "testID"

	t.Run("filter entries with the given filter", func(t *testing.T) {
		dir := t.TempDir()
		var entries []byte

		entries = append(entries, matchingEntry...)
		entries = append(entries, matchingEntry...)
		entries = append(entries, nonMatchingEntry...)
		entries = append(entries, matchingEntry...)

		createFileContent(t, dir, "test.ndjson", bytes.NewBuffer(entries))

		sw := &stackWriter{
			filter: createComponentFilter(matchingID),
		}
		testBuffer := make([]byte, 16) // so the buffer is not aligned
		_, err := printLogFile(filepath.Join(dir, "test.ndjson"), 2, sw, testBuffer)
		require.NoError(t, err)

		var expected []byte
		expected = append(expected, matchingEntry...)
		expected = append(expected, matchingEntry...)
		w := bytes.NewBuffer(nil)
		err = sw.PopAll(w)
		require.NoError(t, err)
		require.Equal(t, string(expected), w.String())
	})

	t.Run("filters out all entries", func(t *testing.T) {
		dir := t.TempDir()
		var entries []byte

		entries = append(entries, nonMatchingEntry...)
		entries = append(entries, nonMatchingEntry...)
		entries = append(entries, nonMatchingEntry...)

		createFileContent(t, dir, "test.ndjson", bytes.NewBuffer(entries))

		sw := &stackWriter{
			filter: createComponentFilter(matchingID),
		}

		testBuffer := make([]byte, 16) // so the buffer is not aligned
		_, err := printLogFile(filepath.Join(dir, "test.ndjson"), 2, sw, testBuffer)
		require.NoError(t, err)

		w := bytes.NewBuffer(nil)
		err = sw.PopAll(w)
		require.NoError(t, err)

		require.Equal(t, "", w.String())
	})

	t.Run("modifies entries with the given modifier", func(t *testing.T) {
		dir := t.TempDir()
		entries := []byte("first\nsecond\n")

		createFileContent(t, dir, "test.ndjson", bytes.NewBuffer(entries))

		sw := &stackWriter{
			modifier: exclamationModifier,
		}
		testBuffer := make([]byte, 4) // so the buffer is not aligned
		_, err := printLogFile(filepath.Join(dir, "test.ndjson"), 2, sw, testBuffer)
		require.NoError(t, err)

		expected := []byte("!first!\n!second!\n")
		w := bytes.NewBuffer(nil)
		err = sw.PopAll(w)
		require.NoError(t, err)
		require.Equal(t, string(expected), w.String())
	})
}

func TestColorModifier(t *testing.T) {
	t.Skip() // remove if you want to see examples of the messages on your terminal
	cases := []struct {
		name string
		msg  []byte
	}{
		{
			name: "debug",
			msg:  []byte(`{"level": "debug", "message": "this is an example"}`),
		},
		{
			name: "info",
			msg:  []byte(`{"level": "info", "message": "this is an example"}`),
		},
		{
			name: "warning",
			msg:  []byte(`{"level": "warning", "message": "this is an example"}`),
		},
		{
			name: "error",
			msg:  []byte(`{"level": "error", "message": "this is an example"}`),
		},
		{
			name: "critical",
			msg:  []byte(`{"level": "critical", "message": "this is an example"}`),
		},
	}

	for _, tc := range cases {
		//nolint:forbidigo // for testing purposes
		fmt.Println(string(addColorModifier(tc.msg)))
	}
}

func TestCreateComponentFilter(t *testing.T) {
	cases := []struct {
		name        string
		componentID string
		entry       []byte
		exp         bool
	}{
		{
			name:        "returns false if the component ID does not match",
			componentID: "requiredID",
			entry:       []byte(`{"component":{"id":"doesNotMatch"}}`),
			exp:         false,
		},
		{
			name:        "returns false if the entry is not valid JSON",
			componentID: "requiredID",
			entry:       []byte(`{"}`),
			exp:         false,
		},
		{
			name:        "returns true if the entry has matching component ID",
			componentID: "requiredID",
			entry:       []byte(`{"component":{"id":"requiredID"}}`),
			exp:         true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter := createComponentFilter(tc.componentID)
			require.Equal(t, tc.exp, filter(tc.entry))
		})
	}
}

func generateLines(prefix string, start, end int) string {
	b := strings.Builder{}
	for i := start; i <= end; i++ {
		b.WriteString(fmt.Sprintf("%s: %d\n", prefix, i))
	}
	return b.String()
}

func createFileEmpty(t *testing.T, dir, name string) {
	createFileContent(t, dir, name, nil)
}

func createFileContent(t *testing.T, dir, name string, content io.Reader) {
	f, err := os.Create(filepath.Join(dir, name))
	require.NoError(t, err)
	defer f.Close()
	if content != nil {
		_, err = io.Copy(f, content)
		require.NoError(t, err)
	}
}

// chanWriter is a simple implementation of the io.Writer interface that
// directs written data at the given channel. This lets us safely monitor
// what is being written during an asynchronous test where printLogs
// is still actively writing to the target io.Writer.
type chanWriter struct {
	ch chan []byte

	// result contains the concatenation of all data that has come through
	// the channel so far. It should only be accessed on the main test
	// goroutine, preferably via the helper function waitUntilMatch, to
	// avoid race conditions.
	result []byte
}

func newChanWriter() *chanWriter {
	return &chanWriter{ch: make(chan []byte)}
}

// Implements the io.Writer interface, to listen for new data
func (cw *chanWriter) Write(p []byte) (int, error) {
	cw.ch <- p
	return len(p), nil
}

// Waits until the combined data written to this object matches the expected
// string (after conversion), or the timeout expires, whichever comes first.
// Reports a fatal test error if the match fails.
func (cw *chanWriter) waitUntilMatch(
	t *testing.T,
	expected string,
	timeout time.Duration,
) {
	t.Helper()
	timeoutChan := time.After(timeout)
	for string(cw.result) != expected {
		select {
		case data := <-cw.ch:
			cw.result = append(cw.result, data...)
		case <-timeoutChan:
			require.FailNow(t, fmt.Sprintf("output does not match. got:\n%v\nexpected:\n%v", string(cw.result), expected))
		}
	}
}
