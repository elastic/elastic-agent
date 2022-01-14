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

package app

import (
	"os/user"
)

// ProcessSpec specifies a way of running a process
type ProcessSpec struct {
	// Binary path.
	BinaryPath string

	// Set of arguments.
	Args          []string
	Configuration map[string]interface{}

	// Under what user we can run the program. (example: apm-server is not running as root, isolation and cgroup)
	User  user.User
	Group user.Group

	// TODO: mapping transformation rules for configuration between elastic-agent.yml and to the beats.
}
