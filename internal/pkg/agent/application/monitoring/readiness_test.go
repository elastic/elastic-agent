// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadinessProcessHTTPHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testCases := []struct {
		name         string
		coord        mockCoordinator
		expectedCode int
		liveness     bool
	}{
		{
			name:         "healthy-nocoord",
			expectedCode: 200,
			liveness:     true,
		},
		{
			name:         "healthy",
			expectedCode: 200,
			liveness:     true,
		},
		{
			name:         "unhealthy",
			expectedCode: 503,
			liveness:     false,
		},
	}

	// test with processesHandler
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			testSrv := httptest.NewServer(createHandler(readinessHandler(test.coord)))
			defer testSrv.Close()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, testSrv.URL, nil)
			require.NoError(t, err)
			res, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			res.Body.Close()
		})
	}

}
