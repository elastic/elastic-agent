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

package retry

// Fatal in retry package is an interface each error needs to implement
// in order to say whether or not it is fatal.
type Fatal interface {
	Fatal() bool
}

// FatalError wraps an error and is always fatal
type FatalError struct {
	error
}

// Fatal determines whether or not error is fatal
func (*FatalError) Fatal() bool {
	return true
}

// ErrorMakeFatal is a shorthand for making an error fatal
func ErrorMakeFatal(err error) error {
	if err == nil {
		return err
	}

	return FatalError{err}
}
