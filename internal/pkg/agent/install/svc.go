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

package install

import (
	"path/filepath"

	"github.com/kardianos/service"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

const (
	// ServiceDisplayName is the service display name for the service.
	ServiceDisplayName = "Elastic Agent"

	// ServiceDescription is the description for the service.
	ServiceDescription = "Elastic Agent is a unified agent to observe, monitor and protect your system."
)

// ExecutablePath returns the path for the installed Agents executable.
func ExecutablePath() string {
	exec := filepath.Join(paths.InstallPath, paths.BinaryName)
	if paths.ShellWrapperPath != "" {
		exec = paths.ShellWrapperPath
	}
	return exec
}

func newService() (service.Service, error) {
	return service.New(nil, &service.Config{
		Name:             paths.ServiceName,
		DisplayName:      ServiceDisplayName,
		Description:      ServiceDescription,
		Executable:       ExecutablePath(),
		WorkingDirectory: paths.InstallPath,
		Option: map[string]interface{}{
			// Linux (systemd) always restart on failure
			"Restart": "always",

			// Windows setup restart on failure
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "1s",
			"OnFailureResetPeriod":   10,
		},
	})
}
