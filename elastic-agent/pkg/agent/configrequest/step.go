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

package configrequest

import "github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/program"

const (
	// StepRun is a name of Start program event
	StepRun = "sc-run"
	// StepRemove is a name of Remove program event causing beat in version to be uninstalled
	StepRemove = "sc-remove"

	// MetaConfigKey is key used to store configuration in metadata
	MetaConfigKey = "config"
)

// Step is a step needed to be applied
type Step struct {
	// ID identifies kind of operation needed to be executed
	ID string
	// Version is a version of a program
	Version string
	// Spec for the program
	ProgramSpec program.Spec
	// Meta contains additional data such as version, configuration or tags.
	Meta map[string]interface{}
}

func (s *Step) String() string {
	return "[ID:" + s.ID + ", PROCESS: " + s.ProgramSpec.Cmd + " VERSION:" + s.Version + "]"
}
