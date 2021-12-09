// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package fleetapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/remote"
)

func authHandler(handler http.HandlerFunc, apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const key = "Authorization"
		const prefix = "ApiKey "

		v := strings.TrimPrefix(r.Header.Get(key), prefix)
		if v != apiKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func withServer(m func(t *testing.T) *http.ServeMux, test func(t *testing.T, host string)) func(t *testing.T) {
	return func(t *testing.T) {
		s := httptest.NewServer(m(t))
		defer s.Close()
		test(t, s.Listener.Addr().String())
	}
}

func withServerWithAuthClient(
	m func(t *testing.T) *http.ServeMux,
	apiKey string,
	test func(t *testing.T, client client.Sender),
) func(t *testing.T) {

	return withServer(m, func(t *testing.T, host string) {
		log, _ := logger.New("", false)
		cfg := remote.Config{
			Host: host,
		}

		client, err := client.NewAuthWithConfig(log, apiKey, cfg)
		require.NoError(t, err)
		test(t, client)
	})
}
