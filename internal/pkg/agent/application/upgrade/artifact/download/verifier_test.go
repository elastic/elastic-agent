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
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
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
			log, obs := logger.NewTesting(tc.Name)
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
