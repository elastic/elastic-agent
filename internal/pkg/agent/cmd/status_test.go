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

package cmd

import (
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/control/client"
)

var testStatus = &client.AgentStatus{
	Status:  client.Healthy,
	Message: "",
	Applications: []*client.ApplicationStatus{{
		ID:      "id_1",
		Name:    "filebeat",
		Status:  client.Healthy,
		Message: "Running",
		Payload: nil,
	}, {
		ID:      "id_2",
		Name:    "metricbeat",
		Status:  client.Healthy,
		Message: "Running",
		Payload: nil,
	}, {
		ID:      "id_3",
		Name:    "filebeat_monitoring",
		Status:  client.Healthy,
		Message: "Running",
		Payload: nil,
	}, {
		ID:      "id_4",
		Name:    "metricbeat_monitoring",
		Status:  client.Healthy,
		Message: "Running",
		Payload: nil,
	},
	},
}

func ExamplehumanStatusOutput() {
	humanStatusOutput(os.Stdout, testStatus)
	// Output:
	// Status: HEALTHY
	// Message: (no message)
	// Applications:
	//   * filebeat               (HEALTHY)
	//                            Running
	//   * metricbeat             (HEALTHY)
	//                            Running
	//   * filebeat_monitoring    (HEALTHY)
	//                            Running
	//   * metricbeat_monitoring  (HEALTHY)
	//                            Running
}

func ExamplejsonOutput() {
	jsonOutput(os.Stdout, testStatus)
	// Output:
	// {
	//     "Status": 2,
	//     "Message": "",
	//     "Applications": [
	//         {
	//             "ID": "id_1",
	//             "Name": "filebeat",
	//             "Status": 2,
	//             "Message": "Running",
	//             "Payload": null
	//         },
	//         {
	//             "ID": "id_2",
	//             "Name": "metricbeat",
	//             "Status": 2,
	//             "Message": "Running",
	//             "Payload": null
	//         },
	//         {
	//             "ID": "id_3",
	//             "Name": "filebeat_monitoring",
	//             "Status": 2,
	//             "Message": "Running",
	//             "Payload": null
	//         },
	//         {
	//             "ID": "id_4",
	//             "Name": "metricbeat_monitoring",
	//             "Status": 2,
	//             "Message": "Running",
	//             "Payload": null
	//         }
	//     ]
	// }
}

func ExampleyamlOutput() {
	yamlOutput(os.Stdout, testStatus)
	// Output:
	// status: 2
	// message: ""
	// applications:
	// - id: id_1
	//   name: filebeat
	//   status: 2
	//   message: Running
	//   payload: {}
	// - id: id_2
	//   name: metricbeat
	//   status: 2
	//   message: Running
	//   payload: {}
	// - id: id_3
	//   name: filebeat_monitoring
	//   status: 2
	//   message: Running
	//   payload: {}
	// - id: id_4
	//   name: metricbeat_monitoring
	//   status: 2
	//   message: Running
	//   payload: {}
}
