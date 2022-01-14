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

import "net/http"

func withHeaders(rtt http.RoundTripper, headers map[string]string) http.RoundTripper {
	if rtt == nil {
		rtt = http.DefaultTransport
	}
	return &rttWithHeaders{target: rtt, headers: headers}
}

type rttWithHeaders struct {
	target  http.RoundTripper
	headers map[string]string
}

func (r *rttWithHeaders) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range r.headers {
		req.Header.Add(k, v)
	}
	return r.target.RoundTrip(req)
}
