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

// add performs x + y
func add(args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("add: accepts exactly 2 arguments; recieved %d", len(args))
	}
	return mathAdd(args[0], args[1])
}

// subtract performs x - y
func subtract(args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("subtract: accepts exactly 2 arguments; recieved %d", len(args))
	}
	return mathSub(args[0], args[1])
}

// multiply performs x * y
func multiply(args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("multiply: accepts exactly 2 arguments; recieved %d", len(args))
	}
	return mathMul(args[0], args[1])
}

// divide performs x / y
func divide(args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("divide: accepts exactly 2 arguments; recieved %d", len(args))
	}
	return mathDiv(args[0], args[1])
}

// modulo performs x % y
func modulo(args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("modulo: accepts exactly 2 arguments; recieved %d", len(args))
	}
	return mathMod(args[0], args[1])
}
