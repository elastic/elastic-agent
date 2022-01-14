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

// +build !darwin,!windows

package paths

const (
	// BinaryName is the name of the installed binary.
	BinaryName = "elastic-agent"

	// InstallPath is the installation path using for install command.
	InstallPath = "/opt/Elastic/Agent"

	// SocketPath is the socket path used when installed.
	SocketPath = "unix:///run/elastic-agent.sock"

	// ServiceName is the service name when installed.
	ServiceName = "elastic-agent"

	// ShellWrapperPath is the path to the installed shell wrapper.
	ShellWrapperPath = "/usr/bin/elastic-agent"

	// ShellWrapper is the wrapper that is installed.
	ShellWrapper = `#!/bin/sh
exec /opt/Elastic/Agent/elastic-agent $@
`
)

// ArePathsEqual determines whether paths are equal taking case sensitivity of os into account.
func ArePathsEqual(expected, actual string) bool {
	return expected == actual
}
