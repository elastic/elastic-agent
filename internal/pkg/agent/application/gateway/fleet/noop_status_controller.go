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

package fleet

import (
	"github.com/elastic/elastic-agent/internal/pkg/core/state"
	"github.com/elastic/elastic-agent/internal/pkg/core/status"
)

type noopController struct{}

func (*noopController) RegisterComponent(_ string) status.Reporter { return &noopReporter{} }
func (*noopController) RegisterComponentWithPersistance(_ string, _ bool) status.Reporter {
	return &noopReporter{}
}
func (*noopController) RegisterApp(_ string, _ string) status.Reporter { return &noopReporter{} }
func (*noopController) Status() status.AgentStatus                     { return status.AgentStatus{Status: status.Healthy} }
func (*noopController) StatusCode() status.AgentStatusCode             { return status.Healthy }
func (*noopController) UpdateStateID(_ string)                         {}
func (*noopController) StatusString() string                           { return "online" }

type noopReporter struct{}

func (*noopReporter) Update(_ state.Status, _ string, _ map[string]interface{}) {}
func (*noopReporter) Unregister()                                               {}
