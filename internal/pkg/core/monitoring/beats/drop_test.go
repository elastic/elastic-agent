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

package beats

import (
	"testing"
)

type testCase struct {
	Endpoint string
	Drop     string
}

func TestMonitoringDrops(t *testing.T) {
	cases := []testCase{
		{`/var/lib/drop/abc.sock`, "/var/lib/drop"},
		{`npipe://drop`, ""},
		{`http+npipe://drop`, ""},
		{`\\.\pipe\drop`, ""},
		{`unix:///var/lib/drop/abc.sock`, "/var/lib/drop"},
		{`http+unix:///var/lib/drop/abc.sock`, "/var/lib/drop"},
		{`file:///var/lib/drop/abc.sock`, "/var/lib/drop"},
		{`http://localhost/stats`, ""},
		{`localhost/stats`, ""},
		{`http://localhost:8080/stats`, ""},
		{`localhost:8080/stats`, ""},
		{`http://1.2.3.4/stats`, ""},
		{`http://1.2.3.4:5678/stats`, ""},
		{`1.2.3.4:5678/stats`, ""},
		{`http://hithere.com:5678/stats`, ""},
		{`hithere.com:5678/stats`, ""},
	}

	for _, c := range cases {
		t.Run(c.Endpoint, func(t *testing.T) {
			drop := monitoringDrop(c.Endpoint)
			if drop != c.Drop {
				t.Errorf("Case[%s]: Expected '%s', got '%s'", c.Endpoint, c.Drop, drop)
			}
		})
	}
}
