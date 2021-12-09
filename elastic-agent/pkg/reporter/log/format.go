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

package log

import (
	"fmt"
	"time"
)

// Format used for logging [DefaultFormat, JSONFormat]
type Format bool

const (
	// DefaultFormat is a log format, resulting in: "2006-01-02T15:04:05: type: 'STATE': event type: 'STARTING' message: Application 'filebeat' is starting."
	DefaultFormat Format = true
	// JSONFormat is a log format, resulting in: {"timestamp": "2006-01-02T15:04:05", "type": "STATE", "event": {"type": "STARTING", "message": "Application 'filebeat' is starting."}
	JSONFormat Format = false
)

const (
	// e.g "2006-01-02T15:04:05 - message: Application 'filebeat' is starting. - type: 'STATE' - event type: 'STARTING'"
	defaultLogFormat = "%s - message: %s - type: '%s' - sub_type: '%s'"
	timeFormat       = time.RFC3339
)

var formatMap = map[string]Format{
	"default": DefaultFormat,
	"json":    JSONFormat,
}

var reverseMap = map[bool]string{
	true:  "default",
	false: "json",
}

// Unpack enables using of string values in config
func (m *Format) Unpack(v string) error {
	mgt, ok := formatMap[v]
	if !ok {
		return fmt.Errorf(
			"unknown format, received '%s' and valid values are default or json",
			v,
		)
	}
	*m = mgt
	return nil
}

// MarshalYAML marshal into a string.
func (m Format) MarshalYAML() (interface{}, error) {
	s, ok := reverseMap[bool(m)]
	if !ok {
		return nil, fmt.Errorf("cannot marshal value of %+v", m)
	}

	return s, nil
}
