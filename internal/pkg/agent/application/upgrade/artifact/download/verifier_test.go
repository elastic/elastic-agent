// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package download

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestPgpBytesFromSource(t *testing.T) {
	testCases := []struct {
		Name         string
		Source       string
		ClientDoErr  error
		ClientBody   []byte
		ClientStatus int

		ExpectedPGP        []byte
		ExpectedErr        error
		ExpectedLogMessage string
	}{
		{
			"successful call",
			PgpSourceURIPrefix + "https://location/path",
			nil,
			[]byte("pgp-body"),
			200,
			[]byte("pgp-body"),
			nil,
			"",
		},
		{
			"unknown source call",
			"https://location/path",
			nil,
			[]byte("pgp-body"),
			200,
			nil,
			ErrUnknownPGPSource,
			"",
		},
		{
			"invalid location is filtered call",
			PgpSourceURIPrefix + "http://location/path",
			nil,
			[]byte("pgp-body"),
			200,
			nil,
			nil,
			"Skipped remote PGP located ",
		},
		{
			"do error is filtered",
			PgpSourceURIPrefix + "https://location/path",
			errors.New("error"),
			[]byte("pgp-body"),
			200,
			nil,
			nil,
			"Skipped remote PGP located",
		},
		{
			"invalid status code is filtered out",
			PgpSourceURIPrefix + "https://location/path",
			nil,
			[]byte("pgp-body"),
			500,
			nil,
			nil,
			"Failed to fetch remote PGP",
		},
		{
			"invalid status code is filtered out",
			PgpSourceURIPrefix + "https://location/path",
			nil,
			[]byte("pgp-body"),
			404,
			nil,
			nil,
			"Failed to fetch remote PGP",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			log, obs := loggertest.New(tc.Name)
			mockClient := &MockClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					if tc.ClientDoErr != nil {
						return nil, tc.ClientDoErr
					}

					return &http.Response{
						StatusCode: tc.ClientStatus,
						Body:       io.NopCloser(bytes.NewReader(tc.ClientBody)),
					}, nil
				},
			}

			resPgp, resErr := PgpBytesFromSource(log, tc.Source, mockClient)
			require.Equal(t, tc.ExpectedErr, resErr)
			require.Equal(t, tc.ExpectedPGP, resPgp)
			if tc.ExpectedLogMessage != "" {
				logs := obs.FilterMessageSnippet(tc.ExpectedLogMessage)
				require.NotEqual(t, 0, logs.Len())
			}

		})
	}
}

func TestVerifySHA512HashWithCleanup_success(t *testing.T) {
	data := "I’m the Doctor. I’m a Time Lord. I’m from the planet " +
		"Gallifrey in the constellation of Kasterborous. I’m 903 years old and " +
		"I’m the man who’s going to save your lives and all 6 billion people on " +
		"the planet below. You got a problem with that?"
	dir := t.TempDir()
	filename := "file"
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	require.NoError(t, err, "could not create file")
	fsha512, err := os.Create(path + ".sha512")
	require.NoError(t, err, "could not create .sha512 file")

	_, err = fmt.Fprint(f, data)
	require.NoError(t, err, "could not write to file")
	hash := sha512.Sum512([]byte(data))
	_, err = fmt.Fprintf(fsha512, "%s %s", hex.EncodeToString(hash[:]), filename)
	require.NoError(t, err, "could not write to file")

	err = f.Close()
	require.NoError(t, err, "could not close file")
	err = fsha512.Close()
	require.NoError(t, err, "could not close .sha512 file")

	err = VerifySHA512HashWithCleanup(testlogger{t: t}, path)
	assert.NoErrorf(t, err, "failed verifying sha512")
}

func TestVerifySHA512HashWithCleanup_failure(t *testing.T) {
	data := "I’m the Doctor. I’m a Time Lord. I’m from the planet " +
		"Gallifrey in the constellation of Kasterborous. I’m 903 years old and " +
		"I’m the man who’s going to save your lives and all 6 billion people on " +
		"the planet below. You got a problem with that?"
	dir := t.TempDir()
	filename := "file"
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	require.NoError(t, err, "could not create file")
	fsha512, err := os.Create(path + ".sha512")
	require.NoError(t, err, "could not create .sha512 file")

	_, err = fmt.Fprint(f, data)
	require.NoError(t, err, "could not write to file")
	_, err = fmt.Fprintf(fsha512, "%s %s", "wrong-sha512", filename)
	require.NoError(t, err, "could not write to file")

	err = f.Close()
	require.NoError(t, err, "could not close file")
	err = fsha512.Close()
	require.NoError(t, err, "could not close .sha512 file")

	err = VerifySHA512HashWithCleanup(testlogger{t: t}, path)
	assert.Errorf(t, err, "checksum verification should have failed")

	dirEntries, err := os.ReadDir(dir)
	require.NoError(t, err, "could not read %q to check it's empty", dir)
	if len(dirEntries) != 0 {
		var files []string
		for _, e := range dirEntries {
			files = append(files, e.Name())
		}

		t.Errorf("there should be no files on %q. Found %v", dir, files)
	}
}

func TestVerifySHA512HashWithCleanup_BrokenHashFile(t *testing.T) {

	const data = "" +
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. " +
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. " +
		"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. " +
		"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
	// if you change data, the constant below should be updated
	const correct_data_hash = "8ba760cac29cb2b2ce66858ead169174057aa1298ccd581514e6db6dee3285280ee6e3a54c9319071dc8165ff061d77783100d449c937ff1fb4cd1bb516a69b9"

	const filename = "lorem_ipsum.txt"
	const hashFileName = filename + ".sha512"

	type skipFunc func(t *testing.T)

	type testcase struct {
		name            string
		skip            skipFunc
		hash            []byte
		hashPermissions fs.FileMode
		wantErr         assert.ErrorAssertionFunc
		wantLogSnippets []string
	}

	testcases := []testcase{
		{
			name:            "happy path - correct hash and format",
			hash:            []byte(correct_data_hash + "  " + filename),
			hashPermissions: 0o640,
			wantErr:         assert.NoError,
		},
		{
			name:            "happy path - broken lines before correct hash and format",
			hash:            []byte("this_is just_filler\n" + "some_more_filler\n" + correct_data_hash + "  " + filename),
			hashPermissions: 0o640,
			wantErr:         assert.NoError,
		},
		{
			name:            "truncated hash line - no filename",
			hash:            []byte(correct_data_hash),
			hashPermissions: 0o640,
			wantErr:         assert.Error,
			wantLogSnippets: []string{`contents: "` + correct_data_hash + `"`},
		},
		{
			name:            "truncated hash",
			hash:            []byte(correct_data_hash[:8] + "  " + filename),
			hashPermissions: 0o640,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				target := new(ChecksumMismatchError)
				return assert.ErrorAs(t, err, &target, "mismatched hash has a specific error type", i)
			},
		},
		{
			name:            "empty hash file",
			hash:            []byte{},
			hashPermissions: 0o640,
			wantErr:         assert.Error,
			wantLogSnippets: []string{`contents: ""`},
		},
		{
			name: "non-existing hash file",
			hash: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, fs.ErrNotExist, i)
			},
		},
		{
			name: "unreadable hash file",
			skip: func(t *testing.T) {
				if runtime.GOOS == "windows" {
					t.Skip("write-only permissions cannot be set on windows")
				}
			},
			hash:            []byte(correct_data_hash + "  " + filename),
			hashPermissions: 0o222,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, fs.ErrPermission, i)
			},
			wantLogSnippets: []string{hashFileName + `", unable do read contents for logging:`},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip != nil {
				tt.skip(t)
			}

			dir := t.TempDir()
			dataFilePath := filepath.Join(dir, filename)
			err := os.WriteFile(dataFilePath, []byte(data), 0o750)
			require.NoError(t, err, "could not write sample data file")

			if tt.hash != nil {
				hashFilePath := filepath.Join(dir, hashFileName)
				err = os.WriteFile(hashFilePath, tt.hash, tt.hashPermissions)
				require.NoError(t, err, "could not write test hash file")
			}

			testLogger, obsLogs := loggertest.New(tt.name)
			err = VerifySHA512HashWithCleanup(testLogger, dataFilePath)
			tt.wantErr(t, err)
			for _, log := range tt.wantLogSnippets {
				filteredLogs := obsLogs.FilterMessageSnippet(log)
				assert.NotEmptyf(t, filteredLogs, "there should be logs matching snippet %q", log)
			}
		})
	}
}

type testlogger struct {
	t *testing.T
}

func (l testlogger) Infof(format string, args ...interface{}) {
	l.t.Logf("[INFO] "+format, args)
}
func (l testlogger) Warnf(format string, args ...interface{}) {
	l.t.Logf("[WARN] "+format, args)
}

type MockClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}
