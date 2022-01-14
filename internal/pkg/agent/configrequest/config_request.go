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

import (
	"strings"
	"time"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/program"
)

const shortID = 8

type configRequest struct {
	id        string
	createdAt time.Time
	programs  []program.Program
}

// New created a new Request.
func New(id string, createdAt time.Time, programs []program.Program) Request {
	return &configRequest{
		id:        id,
		createdAt: createdAt,
		programs:  programs,
	}
}

func (c *configRequest) String() string {
	names := c.ProgramNames()
	return "[" + c.ShortID() + "] Config: " + strings.Join(names, ", ")
}

func (c *configRequest) ID() string {
	return c.id
}

func (c *configRequest) ShortID() string {
	if len(c.id) <= shortID {
		return c.id
	}
	return c.id[0:shortID]
}

func (c *configRequest) CreatedAt() time.Time {
	return c.createdAt
}

func (c *configRequest) Programs() []program.Program {
	return c.programs
}

func (c *configRequest) ProgramNames() []string {
	names := make([]string, 0, len(c.programs))
	for _, name := range c.programs {
		names = append(names, name.Spec.Name)
	}
	return names
}
