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

// +build windows

package control

import (
	"crypto/sha256"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// Address returns the address to connect to Elastic Agent daemon.
func Address() string {
	// when installed the control address is fixed
	if info.RunningInstalled() {
		return paths.SocketPath
	}

	// not install, adjust the path based on data path
	data := paths.Data()
	// entire string cannot be longer than 256 characters, this forces the
	// length to always be 87 characters (but unique per data path)
	return fmt.Sprintf(`\\.\pipe\elastic-agent-%x`, sha256.Sum256([]byte(data)))
}
