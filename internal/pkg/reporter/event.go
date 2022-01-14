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

package reporter

import "time"

// Event is a reported event.
type Event interface {
	Type() string
	SubType() string
	Time() time.Time
	Message() string
	Payload() map[string]interface{}
}

type event struct {
	eventype  string
	subType   string
	timestamp time.Time
	message   string
	payload   map[string]interface{}
}

func (e event) Type() string                    { return e.eventype }
func (e event) SubType() string                 { return e.subType }
func (e event) Time() time.Time                 { return e.timestamp }
func (e event) Message() string                 { return e.message }
func (e event) Payload() map[string]interface{} { return e.payload }
