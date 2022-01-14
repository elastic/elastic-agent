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

package yamltest

import (
	"gopkg.in/yaml.v2"
)

// FromYAML read a bytes slice and return a map[string]interface{}.
// NOTE:OK, The YAML (v2 and v3) parser doesn't work with map as you would expect, it doesn't detect
// map[string]interface{} when parsing the document, it instead uses a map[interface{}]interface{},
// In the following expression, the left side is actually a bool and not a string.
//
// false: "awesome"
func FromYAML(in []byte, out *map[string]interface{}) error {
	var readTo map[interface{}]interface{}
	if err := yaml.Unmarshal(in, &readTo); err != nil {
		return err
	}

	*out = cleanMap(readTo)

	return nil
}

func cleanSlice(in []interface{}) []interface{} {
	result := make([]interface{}, len(in))
	for i, v := range in {
		result[i] = cleanValue(v)
	}
	return result
}

func cleanMap(in map[interface{}]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range in {
		key := k.(string)
		result[key] = cleanValue(v)
	}
	return result
}

func cleanValue(v interface{}) interface{} {
	switch v := v.(type) {
	case []interface{}:
		return cleanSlice(v)
	case map[interface{}]interface{}:
		return cleanMap(v)
	default:
		return v
	}
}
