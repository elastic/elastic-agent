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

package fleetapi

import (
	"encoding/json"
	"time"
)

const timeFormat = time.RFC3339Nano

// Time is a custom time that impose the serialization format.
type Time time.Time

// MarshalJSON make sure that all the times are serialized with the RFC3339 format.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).Format(timeFormat))
}
