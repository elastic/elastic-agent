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

// +build !windows

package control

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// Address returns the address to connect to Elastic Agent daemon.
func Address() string {
	// when installed the control address is fixed
	if info.RunningInstalled() {
		return paths.SocketPath
	}

	// unix socket path must be less than 104 characters
	path := fmt.Sprintf("unix://%s.sock", filepath.Join(paths.TempDir(), "elastic-agent-control"))
	if len(path) < 104 {
		return path
	}
	// place in global /tmp to ensure that its small enough to fit; current path is way to long
	// for it to be used, but needs to be unique per Agent (in the case that multiple are running)
	return fmt.Sprintf(`unix:///tmp/elastic-agent/%x.sock`, sha256.Sum256([]byte(path)))
}
