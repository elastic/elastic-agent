// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package enroll

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fleetclient "github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/stretchr/testify/require"
)

func Test_CheckRemote(t *testing.T) {
	var reportedStatus int
	statusServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Path, "status") {
				w.WriteHeader(http.StatusNotFound)
				_, err := w.Write(nil)
				require.NoError(t, err)
				return
			}

			w.WriteHeader(reportedStatus)
			_, err := w.Write(nil)
			require.NoError(t, err)

		}))
	defer statusServer.Close()

	cases := []struct {
		name          string
		serverStatus  int
		expectedError bool
	}{
		{"ok", http.StatusOK, false},
		{"4xx", http.StatusNotFound, true},
		{"5xx", http.StatusInternalServerError, true},
	}

	testLogger, _ := loggertest.New("test_CheckRemote")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reportedStatus = tc.serverStatus
			c, err := fleetclient.NewWithConfig(testLogger, remote.Config{
				Host: statusServer.URL,
			})

			require.NoError(t, err)
			require.Equal(t, tc.expectedError, CheckRemote(t.Context(), c) != nil)
		})
	}
}
