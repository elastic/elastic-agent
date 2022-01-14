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

// callFunc is a function called while the expression evaluation is done, the function is responsible
// of doing the type conversion and allow checking the arity of the function.
type callFunc func(args []interface{}) (interface{}, error)

// methods are the methods enabled in EQL.
var methods = map[string]callFunc{
	// array
	"arrayContains": arrayContains,

	// dict
	"hasKey": hasKey,

	// length:
	"length": length,

	// math
	"add":      add,
	"subtract": subtract,
	"multiply": multiply,
	"divide":   divide,
	"modulo":   modulo,

	// str
	"concat":         concat,
	"endsWith":       endsWith,
	"indexOf":        indexOf,
	"match":          match,
	"number":         number,
	"startsWith":     startsWith,
	"string":         str,
	"stringContains": stringContains,
}
