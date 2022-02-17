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

package client

import (
	"errors"
	"net/http"

	"github.com/elastic/elastic-agent/internal/pkg/remote"
)

// ErrInvalidAPIKey is returned when authentication fail to fleet.
var ErrInvalidAPIKey = errors.New("invalid api key to authenticate with fleet")

// FleetUserAgentRoundTripper adds the Fleet user agent.
type FleetUserAgentRoundTripper struct {
	rt http.RoundTripper
}

// RoundTrip adds the Fleet user agent string to every request.
func (r *FleetUserAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.rt.RoundTrip(req)
}

// NewFleetUserAgentRoundTripper returns a  FleetUserAgentRoundTripper that actually wrap the
// existing UserAgentRoundTripper with a specific string.
func NewFleetUserAgentRoundTripper(wrapped http.RoundTripper, version string) http.RoundTripper {
	const name = "Elastic Agent"
	return &FleetUserAgentRoundTripper{
		rt: remote.NewUserAgentRoundTripper(wrapped, name+" v"+version),
	}
}

// FleetAuthRoundTripper allow all calls to be authenticated using the api key.
// The token is added as a header key.
type FleetAuthRoundTripper struct {
	rt     http.RoundTripper
	apiKey string
}

// RoundTrip makes all the calls to the service authenticated.
func (r *FleetAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	const key = "Authorization"
	const prefix = "ApiKey "

	req.Header.Set(key, prefix+r.apiKey)
	resp, err := r.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		defer resp.Body.Close()
		return nil, ErrInvalidAPIKey
	}

	return resp, err
}

// NewFleetAuthRoundTripper wrap an existing http.RoundTripper and adds the API in the header.
func NewFleetAuthRoundTripper(
	wrapped http.RoundTripper,
	apiKey string,
) (http.RoundTripper, error) {
	if len(apiKey) == 0 {
		return nil, errors.New("empty api key received")
	}
	return &FleetAuthRoundTripper{rt: wrapped, apiKey: apiKey}, nil
}
