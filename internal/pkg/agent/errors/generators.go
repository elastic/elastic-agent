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

package errors

// M creates a meta entry for an error
func M(key string, val interface{}) MetaRecord {
	return MetaRecord{key: key,
		val: val,
	}
}

// New constructs an Agent Error based on provided parameteres.
// Accepts:
// - string for error message [0..1]
// - error for inner error [0..1]
// - ErrorType for defining type [0..1]
// - MetaRecords for enhancing error with metadata [0..*]
// If optional arguments are provided more than once (message, error, type), then
// last argument overwrites previous ones.
func New(args ...interface{}) error {
	agentErr := agentError{}
	agentErr.meta = make(map[string]interface{})

	for _, arg := range args {
		switch arg := arg.(type) {
		case string:
			agentErr.msg = arg
		case error:
			agentErr.err = arg
		case ErrorType:
			agentErr.errType = arg
		case MetaRecord:
			agentErr.meta[arg.key] = arg.val
		}
	}

	return agentErr
}
