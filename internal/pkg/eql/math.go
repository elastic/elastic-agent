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

func mathAdd(left, right operand) (interface{}, error) {
	switch v := left.(type) {
	case int:
		switch rv := right.(type) {
		case int:
			return v + rv, nil
		case float64:
			return float64(v) + rv, nil
		default:
			return 0, fmt.Errorf(
				"math: +, incompatible type to add both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case float64:
		switch rv := right.(type) {
		case int:
			return v + float64(rv), nil
		case float64:
			return v + rv, nil
		default:
			return 0, fmt.Errorf(
				"math: +, incompatible type to add both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	default:
		return 0, fmt.Errorf(
			"math: +, incompatible type to add both operands must be numbers, left=%T, right=%T",
			left,
			right,
		)
	}
}

func mathSub(left, right operand) (interface{}, error) {
	switch v := left.(type) {
	case int:
		switch rv := right.(type) {
		case int:
			return v - rv, nil
		case float64:
			return float64(v) - rv, nil
		default:
			return 0, fmt.Errorf(
				"math: -, incompatible type to subtract both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case float64:
		switch rv := right.(type) {
		case int:
			return v - float64(rv), nil
		case float64:
			return v - rv, nil
		default:
			return 0, fmt.Errorf(
				"math: -, incompatible type to subtract both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	default:
		return 0, fmt.Errorf(
			"math: -, incompatible type to subtract both operands must be numbers, left=%T, right=%T",
			left,
			right,
		)
	}
}

func mathMul(left, right operand) (interface{}, error) {
	switch v := left.(type) {
	case int:
		switch rv := right.(type) {
		case int:
			return v * rv, nil
		case float64:
			return float64(v) * rv, nil
		default:
			return 0, fmt.Errorf(
				"math: *, incompatible type to multiply both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case float64:
		switch rv := right.(type) {
		case int:
			return v * float64(rv), nil
		case float64:
			return v * rv, nil
		default:
			return 0, fmt.Errorf(
				"math: *, incompatible type to multiply both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	default:
		return 0, fmt.Errorf(
			"math: *, incompatible type to multiply both operands must be numbers, left=%T, right=%T",
			left,
			right,
		)
	}
}

func mathDiv(left, right operand) (interface{}, error) {
	switch v := left.(type) {
	case int:
		switch rv := right.(type) {
		case int:
			if rv == 0 {
				return 0, fmt.Errorf(
					"math: /, division by zero, left=%T, right=%T",
					left,
					right,
				)
			}
			return v / rv, nil
		case float64:
			if rv == 0 {
				return 0, fmt.Errorf(
					"math: /, division by zero, left=%T, right=%T",
					left,
					right,
				)
			}
			return float64(v) / rv, nil
		default:
			return 0, fmt.Errorf(
				"math: /, incompatible type to divide both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case float64:
		switch rv := right.(type) {
		case int:
			if rv == 0 {
				return 0, fmt.Errorf(
					"math: /, division by zero, left=%T, right=%T",
					left,
					right,
				)
			}
			return v / float64(rv), nil
		case float64:
			if rv == 0 {
				return 0, fmt.Errorf(
					"math: /, division by zero, left=%T, right=%T",
					left,
					right,
				)
			}
			return v / rv, nil
		default:
			return 0, fmt.Errorf(
				"math: /, incompatible type to divide both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	default:
		return 0, fmt.Errorf(
			"math: /, incompatible type to divide both operands must be numbers, left=%T, right=%T",
			left,
			right,
		)
	}
}

func mathMod(left, right operand) (interface{}, error) {
	switch v := left.(type) {
	case int:
		switch rv := right.(type) {
		case int:
			if rv == 0 {
				return 0, fmt.Errorf(
					"math: %%, division by zero, left=%T, right=%T",
					left,
					right,
				)
			}
			return v % rv, nil
		default:
			return 0, fmt.Errorf(
				"math: %%, incompatible type to modulus both operands must be integers, left=%T, right=%T",
				left,
				right,
			)
		}
	default:
		return 0, fmt.Errorf(
			"math: %%, incompatible type to modulus both operands must be integers, left=%T, right=%T",
			left,
			right,
		)
	}
}
