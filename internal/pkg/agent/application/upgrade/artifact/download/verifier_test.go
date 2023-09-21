// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package download

import (
	"bytes"
	"io"
	"net/http"
	"testing"

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

type MockClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}
