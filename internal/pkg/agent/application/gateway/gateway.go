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

package gateway

import "github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"

// FleetGateway is a gateway between the Agent and the Fleet API, it's take cares of all the
// bidirectional communication requirements. The gateway aggregates events and will periodically
// call the API to send the events and will receive actions to be executed locally.
// The only supported action for now is a "ActionPolicyChange".
type FleetGateway interface {
	// Start starts the gateway.
	Start() error

	// Set the client for the gateway.
	SetClient(client.Sender)
}
