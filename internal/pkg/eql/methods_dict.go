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

package eql

import "fmt"

// hasKey check if dict has anyone of the provided keys.
func hasKey(args []interface{}) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("hasKey: accepts minimum 2 arguments; recieved %d", len(args))
	}
	switch d := args[0].(type) {
	case *null:
		return false, nil
	case map[string]interface{}:
		for i, check := range args[1:] {
			switch c := check.(type) {
			case string:
				_, ok := d[c]
				if ok {
					return true, nil
				}
			default:
				return nil, fmt.Errorf("hasKey: %d argument must be a string; recieved %T", i+1, check)
			}
		}
		return false, nil
	}
	return nil, fmt.Errorf("hasKey: first argument must be a dictionary; recieved %T", args[0])
}
