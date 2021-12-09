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

package remote

import (
	"fmt"
	"time"

	"github.com/elastic/beats/v7/libbeat/common/transport/httpcommon"
)

// Config is the configuration for the client.
type Config struct {
	Protocol Protocol `config:"protocol" yaml:"protocol"`
	SpaceID  string   `config:"space.id" yaml:"space.id,omitempty"`
	Path     string   `config:"path" yaml:"path,omitempty"`
	Host     string   `config:"host" yaml:"host,omitempty"`
	Hosts    []string `config:"hosts" yaml:"hosts,omitempty"`

	Transport httpcommon.HTTPTransportSettings `config:",inline" yaml:",inline"`
}

// Protocol define the protocol to use to make the connection. (Either HTTPS or HTTP)
type Protocol string

const (
	// ProtocolHTTP is HTTP protocol connection.
	ProtocolHTTP Protocol = "http"
	// ProtocolHTTPS is HTTPS protocol connection.
	ProtocolHTTPS Protocol = "https"
)

// Unpack the protocol.
func (p *Protocol) Unpack(from string) error {
	if Protocol(from) != ProtocolHTTPS && Protocol(from) != ProtocolHTTP {
		return fmt.Errorf("invalid protocol %s, accepted values are 'http' and 'https'", from)
	}

	*p = Protocol(from)
	return nil
}

// DefaultClientConfig creates default configuration for client.
func DefaultClientConfig() Config {
	transport := httpcommon.DefaultHTTPTransportSettings()
	// Default timeout 10 minutes, expecting Fleet Server to control the long poll with default timeout of 5 minutes
	transport.Timeout = 10 * time.Minute

	return Config{
		Protocol:  ProtocolHTTP,
		Host:      "localhost:5601",
		Path:      "",
		SpaceID:   "",
		Transport: transport,
	}
}

// GetHosts returns the hosts to connect.
//
// This looks first at `Hosts` and then at `Host` when `Hosts` is not defined.
func (c *Config) GetHosts() []string {
	if len(c.Hosts) > 0 {
		return c.Hosts
	}
	return []string{c.Host}
}
