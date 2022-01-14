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

// length returns the length of the string, array, or dictionary
func length(args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("length: accepts exactly 1 argument; recieved %d", len(args))
	}
	switch a := args[0].(type) {
	case *null:
		return 0, nil
	case string:
		return len(a), nil
	case []interface{}:
		return len(a), nil
	case map[string]interface{}:
		return len(a), nil
	}
	return nil, fmt.Errorf("length: accepts only a string, array, or dictionary; recieved %T", args[0])
}
