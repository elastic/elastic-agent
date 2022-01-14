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

package http

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-poc/internal/pkg/release"
)

func TestAddingHeaders(t *testing.T) {
	msg := []byte("OK")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, fmt.Sprintf("Beat elastic-agent v%s", release.Version()), req.Header.Get("User-Agent"))
		w.Write(msg)
	}))
	defer server.Close()

	c := server.Client()
	rtt := withHeaders(c.Transport, headers)

	c.Transport = rtt
	resp, err := c.Get(server.URL)
	require.NoError(t, err)
	b, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, b, msg)
}
