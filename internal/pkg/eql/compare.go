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

import (
	"fmt"
	"sort"
)

type operand interface{}

func compareEQ(left, right operand) (bool, error) {
	switch v := left.(type) {
	case *null:
		_, ok := right.(*null)
		if ok {
			return true, nil
		}
		return false, nil
	case bool:
		rV, ok := right.(bool)
		if !ok {
			return false, nil
		}
		if rV == v {
			return true, nil
		}
		return false, nil
	case int:
		switch rv := right.(type) {
		case *null:
			return false, nil
		case int:
			return v == rv, nil
		case float64:
			// TODO: check overflow, weird things will happen with precision here.
			// use modf
			return float64(v) == rv, nil
		default:
			return false, fmt.Errorf(
				"compare: ==, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case float64:
		switch rv := right.(type) {
		case *null:
			return false, nil
		case int:
			return v == float64(rv), nil
		case float64:
			return v == rv, nil
		default:
			return false, fmt.Errorf(
				"compare: ==, incompatible type to compare both operand must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case string:
		rV, ok := right.(string)
		if !ok {
			return false, nil
		}
		if rV == v {
			return true, nil
		}
		return false, nil
	case []interface{}:
		rV, ok := right.([]interface{})
		if !ok {
			return false, nil
		}
		if len(v) != len(rV) {
			return false, nil
		}
		for i := range v {
			b, err := compareEQ(v[i], rV[i])
			if err != nil {
				return false, err
			}
			if !b {
				return false, nil
			}
		}
		return true, nil
	case map[string]interface{}:
		rV, ok := right.(map[string]interface{})
		if !ok {
			return false, nil
		}
		if !keysEqual(v, rV) {
			return false, nil
		}
		for i := range v {
			b, err := compareEQ(v[i], rV[i])
			if err != nil {
				return false, err
			}
			if !b {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf(
			"compare: ==, incompatible type to compare, left=%T, right=%T",
			left,
			right,
		)
	}
}

func compareNEQ(left, right operand) (bool, error) {
	switch v := left.(type) {
	case *null:
		_, ok := right.(*null)
		if ok {
			return false, nil
		}
		return true, nil
	case bool:
		rV, ok := right.(bool)
		if !ok {
			return true, nil
		}
		if rV == v {
			return false, nil
		}
		return true, nil
	case int:
		switch rv := right.(type) {
		case *null:
			return true, nil
		case int:
			return v != rv, nil
		case float64:
			// TODO: check overflow, weird things will happen with precision here.
			// use modf
			return float64(v) != rv, nil
		default:
			return false, fmt.Errorf(
				"compare: ==, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case float64:
		switch rv := right.(type) {
		case *null:
			return true, nil
		case int:
			return v != float64(rv), nil
		case float64:
			return v != rv, nil
		default:
			return false, fmt.Errorf(
				"compare: ==, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case string:
		rV, ok := right.(string)
		if !ok {
			return true, nil
		}
		if rV == v {
			return false, nil
		}
		return true, nil
	case []interface{}:
		rV, ok := right.([]interface{})
		if !ok {
			return true, nil
		}
		if len(v) != len(rV) {
			return true, nil
		}
		for i := range v {
			b, err := compareNEQ(v[i], rV[i])
			if err != nil {
				return false, err
			}
			if b {
				return true, nil
			}
		}
		return false, nil
	case map[string]interface{}:
		rV, ok := right.(map[string]interface{})
		if !ok {
			return true, nil
		}
		if !keysEqual(v, rV) {
			return true, nil
		}
		for i := range v {
			b, err := compareNEQ(v[i], rV[i])
			if err != nil {
				return false, err
			}
			if b {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf(
			"compare: !=, incompatible type to compare, left=%T, right=%T",
			left,
			right,
		)
	}
}

func compareLT(left, right operand) (bool, error) {
	switch v := left.(type) {
	case int:
		switch rv := right.(type) {
		case int:
			return v < rv, nil
		case float64:
			return float64(v) < rv, nil
		default:
			return false, fmt.Errorf(
				"compare: <, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case float64:
		switch rv := right.(type) {
		case int:
			return v < float64(rv), nil
		case float64:
			return v < rv, nil
		default:
			return false, fmt.Errorf(
				"compare: <, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	default:
		return false, fmt.Errorf(
			"compare: <, incompatible type to compare both operands must be numbers, left=%T, right=%T",
			left,
			right,
		)
	}
}

func compareLTE(left, right operand) (bool, error) {
	switch v := left.(type) {
	case int:
		switch rv := right.(type) {
		case int:
			return v <= rv, nil
		case float64:
			return float64(v) <= rv, nil
		default:
			return false, fmt.Errorf(
				"compare: <=, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case float64:
		switch rv := right.(type) {
		case int:
			return v <= float64(rv), nil
		case float64:
			return v <= rv, nil
		default:
			return false, fmt.Errorf(
				"compare: <=, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	default:
		return false, fmt.Errorf(
			"compare: <=, incompatible type to compare both operands must be numbers, left=%T, right=%T",
			left,
			right,
		)
	}
}

func compareGT(left, right operand) (bool, error) {
	switch v := left.(type) {
	case int:
		switch rv := right.(type) {
		case int:
			return v > rv, nil
		case float64:
			return float64(v) > rv, nil
		default:
			return false, fmt.Errorf(
				"compare: >, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case float64:
		switch rv := right.(type) {
		case int:
			return v > float64(rv), nil
		case float64:
			return v > rv, nil
		default:
			return false, fmt.Errorf(
				"compare: >, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	default:
		return false, fmt.Errorf(
			"compare: >, incompatible type to compare both operands must be numbers, left=%T, right=%T",
			left,
			right,
		)
	}
}

func compareGTE(left, right operand) (bool, error) {
	switch v := left.(type) {
	case int:
		switch rv := right.(type) {
		case int:
			return v >= rv, nil
		case float64:
			return float64(v) >= rv, nil
		default:
			return false, fmt.Errorf(
				"compare: >=, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	case float64:
		switch rv := right.(type) {
		case int:
			return v >= float64(rv), nil
		case float64:
			return v >= rv, nil
		default:
			return false, fmt.Errorf(
				"compare: >=, incompatible type to compare both operands must be numbers, left=%T, right=%T",
				left,
				right,
			)
		}
	default:
		return false, fmt.Errorf(
			"compare: >=, incompatible type to compare both operands must be numbers, left=%T, right=%T",
			left,
			right,
		)
	}
}

func logicalAND(left, right operand) (bool, error) {
	switch l := left.(type) {
	case bool:
		switch r := right.(type) {
		case bool:
			return l && r, nil
		}
	}
	return false, fmt.Errorf(
		"and: incompatible type to and both operands must be booleans, left=%T, right=%T",
		left,
		right,
	)
}

func logicalOR(left, right operand) (bool, error) {
	switch l := left.(type) {
	case bool:
		switch r := right.(type) {
		case bool:
			return l || r, nil
		}
	}
	return false, fmt.Errorf(
		"and: incompatible type to and both operands must be booleans, left=%T, right=%T",
		left,
		right,
	)
}

func keys(v map[string]interface{}) []string {
	ks := make([]string, len(v))
	i := 0
	for k := range v {
		ks[i] = k
		i++
	}
	sort.Strings(ks)
	return ks
}

func keysEqual(v1, v2 map[string]interface{}) bool {
	ks1 := keys(v1)
	ks2 := keys(v2)
	if len(ks1) != len(ks2) {
		return false
	}
	for i, v := range ks1 {
		if v != ks2[i] {
			return false
		}
	}
	return true
}
